package loom

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"spip/internal/config"
)

// The shipper is the second copy of every ECS record (the local log is the
// first), and it is made durable on the sensor's own disk. Two goroutines
// keep the network away from the capture path:
//
//	batcher  takes records off the channel, encodes each one exactly as before
//	         and closes a batch on batch_size, on the body size bound, or on
//	         flush_interval. The closed batch is written to the spool. No
//	         network I/O happens here, so the channel keeps draining while
//	         Loom is down.
//	sender   posts the spool's oldest batch, deletes it after a 2xx and
//	         moves on; after a failure it waits with a doubling pause and
//	         tries the same batch again, so an outage of hours is replayed
//	         once Loom answers.
//
// Before the spool, a batch got three attempts inside the batcher and was then
// dropped, and the batcher blocked on those attempts while the channel filled
// and the logger shed records. On 2026-10-18 a 28-minute Loom outage cost
// about 20 minutes of Spip records that way.
//
// Status handling, matching what Loom answers:
//
//	2xx          delivered: the batch is deleted and never sent again.
//	413          over max_body_size_bytes or max_event_size_bytes: the batch
//	             is halved in the spool until each part fits; a single record
//	             Loom still refuses is dropped with a log line.
//	429          Loom's request or event budget: retried after Retry-After.
//	400, 415     our own body, malformed: a retry cannot help, dropped.
//	other        5xx, transport errors, 401/403 (a token fixed on either side
//	             should deliver what waited): kept and retried.

const (
	channelCapacity = 256
	clientTimeout   = 15 * time.Second

	// Loom takes at most 500 records and 8 MiB a request; batches are
	// closed at half the body limit so a split is rare.
	maxBatchEvents = 500
	maxBodyBytes   = 4 << 20
	defaultBackoff = time.Second
	maxBackoff     = time.Minute
	shutdownGrace  = 5 * time.Second
	minFreeBytes   = 128 << 20 // the spool leaves this much of the disk free
	memQueueMax    = 8 << 20   // fallback when the spool cannot be written
)

// fallbackSpoolDir is tried when the configured spool directory cannot be
// used.
var fallbackSpoolDir = filepath.Join(os.TempDir(), "spip-loom-spool")

// maxRetryAfter bounds how long one rate-limited batch can hold the shipper.
const maxRetryAfter = 10 * time.Second

type Shipper struct {
	cfg     *config.LoomConfig
	client  *http.Client
	inCh    chan map[string]interface{}
	done    chan struct{}
	onError func(string)

	spool *Spool    // nil when no directory could be used
	mem   *memQueue // batches the spool could not take

	maxBody    int
	backoff    time.Duration
	maxBackoff time.Duration

	kick       chan struct{}
	stop       chan struct{}
	senderDone chan struct{}

	shipped atomic.Uint64
	drops   sync.Map // reason -> *hourly
}

// NewShipper opens the spool and prepares the shipper; Run starts it. It
// never fails: when neither the configured spool directory nor a fallback in
// the system temp directory can be used, batches are held in a small bounded
// memory queue instead, and that is logged.
func NewShipper(cfg *config.LoomConfig, onError func(string)) *Shipper {
	var transport http.RoundTripper = http.DefaultTransport
	if cfg.InsecureSkipVerify {
		transport = &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}
	}
	s := &Shipper{
		cfg:        cfg,
		client:     &http.Client{Timeout: clientTimeout, Transport: transport},
		inCh:       make(chan map[string]interface{}, channelCapacity),
		done:       make(chan struct{}),
		onError:    onError,
		maxBody:    maxBodyBytes,
		backoff:    defaultBackoff,
		maxBackoff: maxBackoff,
		kick:       make(chan struct{}, 1),
		stop:       make(chan struct{}),
		senderDone: make(chan struct{}),
	}
	s.mem = &memQueue{max: memQueueMax, onDrop: s.noteDrop}

	dir := cfg.SpoolDir
	if dir == "" {
		dir = config.DefaultSpoolDirName
	}
	spool, err := OpenSpool(dir, cfg.SpoolMaxBytes(), cfg.SpoolMaxAgeDuration(), minFreeBytes)
	if err != nil {
		fallback := fallbackSpoolDir
		onError(fmt.Sprintf("spool %s: %v; using %s", dir, err, fallback))
		spool, err = OpenSpool(fallback, cfg.SpoolMaxBytes(), cfg.SpoolMaxAgeDuration(), minFreeBytes)
		if err != nil {
			onError(fmt.Sprintf("spool %s: %v; batches wait in memory (%d MB at most) and an outage longer than that loses records", fallback, err, memQueueMax>>20))
			spool = nil
		}
	}
	if spool != nil {
		spool.onDrop = s.noteDrop
		s.spool = spool
		if files, size, docs := spool.Stats(); files > 0 {
			onError(fmt.Sprintf("%d records in %d spooled batches (%d KB) from an earlier run, sending them first", docs, files, size>>10))
		}
	}
	return s
}

// hourly logs an event the first time and then at most once an hour, with the
// running count.
type hourly struct {
	count atomic.Uint64
	last  atomic.Int64
}

var dropWhy = map[string]string{
	"size":    "the spool reached its size cap, the oldest %d records were removed unsent",
	"age":     "%d spooled records passed the spool's age cap and were removed unsent",
	"disk":    "the disk is nearly full, %d records were removed from the spool unsent",
	"corrupt": "%d records in an unreadable spool file were removed",
	"lowdisk": "the disk is nearly full even with the spool emptied, %d records were held in memory instead",
	"memory":  "the in-memory fallback queue is full, the oldest %d records were removed unsent",
}

// noteDrop counts records removed unsent (or, for "lowdisk", kept in memory
// rather than on disk) and logs the first such event per reason, then at most
// once an hour. The local log still has every record.
func (s *Shipper) noteDrop(reason string, docs int) {
	v, _ := s.drops.LoadOrStore(reason, &hourly{})
	h := v.(*hourly)
	total := h.count.Add(uint64(docs))
	now := time.Now().Unix()
	last := h.last.Load()
	if (last == 0 || now-last >= 3600) && h.last.CompareAndSwap(last, now) {
		s.onError(fmt.Sprintf(dropWhy[reason]+" (%d since start; the local log has them)", docs, total))
	}
}

// Dropped is the number of records removed unsent for reason since start.
func (s *Shipper) Dropped(reason string) uint64 {
	if v, ok := s.drops.Load(reason); ok {
		return v.(*hourly).count.Load()
	}
	return 0
}

// Shipped is the number of records Loom accepted since start.
func (s *Shipper) Shipped() uint64 { return s.shipped.Load() }

func (s *Shipper) Run() (chan<- map[string]interface{}, <-chan struct{}) {
	batchSize := s.cfg.BatchSize
	if batchSize <= 0 {
		batchSize = 50
	}
	batchSize = min(batchSize, maxBatchEvents)
	interval := s.cfg.FlushIntervalDuration()
	if interval <= 0 {
		interval = 10 * time.Second
	}

	var docs [][]byte
	size := 0
	flush := func() {
		if len(docs) == 0 {
			return
		}
		s.store(joinDocs(rawDocs(docs)), len(docs))
		docs, size = nil, 0
	}

	go s.send()
	s.wake() // batches left by an earlier run go out without waiting for new ones
	go func() {
		defer close(s.done)
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case ev, ok := <-s.inCh:
				if !ok {
					flush()
					return
				}
				// Each record is encoded on its own; joined with commas
				// inside brackets this is byte for byte what
				// json.Marshal of the whole batch produced before.
				b, err := json.Marshal(ev)
				if err != nil {
					s.onError(fmt.Sprintf("marshal: %v", err))
					continue
				}
				if len(docs) > 0 && size+len(b)+1 > s.maxBody {
					flush()
				}
				docs = append(docs, b)
				size += len(b) + 1
				if len(docs) >= batchSize {
					flush()
				}
			case <-ticker.C:
				flush()
			}
		}
	}()

	return s.inCh, s.done
}

func rawDocs(docs [][]byte) []json.RawMessage {
	out := make([]json.RawMessage, len(docs))
	for i, d := range docs {
		out[i] = d
	}
	return out
}

// store hands a closed batch to the spool, or to the memory queue when the
// spool cannot take it, and wakes the sender.
func (s *Shipper) store(body []byte, n int) {
	if s.spool != nil {
		err := s.spool.Put(body, n)
		if err == nil {
			s.wake()
			return
		}
		if errors.Is(err, errLowDisk) {
			s.noteDrop("lowdisk", n)
		} else {
			s.onError(fmt.Sprintf("spool write: %v; batch of %d records held in memory", err, n))
		}
	}
	s.mem.Put(body, n)
	s.wake()
}

func (s *Shipper) wake() {
	select {
	case s.kick <- struct{}{}:
	default:
	}
}

// send is the sender loop: it posts what is queued, oldest first, and pauses
// with a doubling backoff after a failure.
func (s *Shipper) send() {
	defer close(s.senderDone)
	backoff := s.backoff
	failing := false
	var retry <-chan time.Time
	for {
		select {
		case <-s.stop:
			return
		case <-s.kick:
		case <-retry:
			retry = nil
		}
		if retry != nil {
			continue // waiting out a failure; new batches queue behind the oldest
		}
		wait, ok := s.drain(context.Background())
		if ok {
			if failing {
				s.onError(fmt.Sprintf("Loom reachable again, spool drained (%d records shipped since start)", s.shipped.Load()))
				failing = false
			}
			backoff = s.backoff
			continue
		}
		failing = true
		if wait <= 0 {
			wait = backoff
			backoff = min(backoff*2, s.maxBackoff)
		}
		retry = time.After(wait)
	}
}

// queue is what the sender drains: the spool, or the memory fallback.
type queue interface {
	Oldest() (name string, body []byte, n int, ok bool)
	Remove(name string) error
	Split(name string, body []byte) (bool, error)
	Stats() (files int, bytes int64, docs int)
}

// next returns the queue holding the oldest batch to post, spool first.
func (s *Shipper) next() (queue, string, []byte, int, bool) {
	if s.spool != nil {
		if name, body, n, ok := s.spool.Oldest(); ok {
			return s.spool, name, body, n, true
		}
	}
	if name, body, n, ok := s.mem.Oldest(); ok {
		return s.mem, name, body, n, true
	}
	return nil, "", nil, 0, false
}

// drain posts queued batches oldest first until nothing is left (ok true) or
// a post fails (ok false, with the pause Loom asked for, or 0 for the
// caller's backoff).
func (s *Shipper) drain(ctx context.Context) (wait time.Duration, ok bool) {
	for {
		q, name, body, n, found := s.next()
		if !found {
			return 0, true
		}
		status, retryAfter, err := s.post(ctx, body)
		if err != nil {
			if ctx.Err() == nil {
				s.onError(fmt.Sprintf("POST: %v; %s", err, s.pending()))
			}
			return 0, false
		}
		switch {
		case status >= 200 && status < 300:
			if err := q.Remove(name); err != nil {
				s.onError(fmt.Sprintf("spool: delivered batch %s could not be deleted and may be sent again after a restart: %v", name, err))
			}
			s.shipped.Add(uint64(n))
		case status == http.StatusRequestEntityTooLarge:
			split, err := q.Split(name, body)
			if err != nil {
				s.onError(fmt.Sprintf("split: %v", err))
			}
			if !split {
				_ = q.Remove(name)
				s.onError(fmt.Sprintf("POST: Loom refused a single record of %d bytes as too large, dropped; the local log has it", len(body)))
			}
		case status == http.StatusTooManyRequests:
			s.onError(fmt.Sprintf("POST: rate limited, retrying after %v", retryAfter))
			return retryAfter, false
		case status == http.StatusBadRequest || status == http.StatusUnsupportedMediaType:
			_ = q.Remove(name)
			s.onError(fmt.Sprintf("POST: status %d, dropping %d records; the local log has them", status, n))
		default:
			s.onError(fmt.Sprintf("POST: status %d; %s", status, s.pending()))
			return 0, false
		}
	}
}

// post sends one batch and returns the status, and the pause a 429 asked for.
func (s *Shipper) post(ctx context.Context, body []byte) (int, time.Duration, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.cfg.URL, bytes.NewReader(body))
	if err != nil {
		return 0, 0, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Spip-ID", s.cfg.SensorID)
	req.Header.Set("Authorization", "Bearer "+s.cfg.Token)
	resp, err := s.client.Do(req)
	if err != nil {
		return 0, 0, err
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
	resp.Body.Close()
	return resp.StatusCode, parseRetryAfter(resp.Header.Get("Retry-After")), nil
}

// parseRetryAfter reads a delay in seconds; dates and junk fall back to 1s.
func parseRetryAfter(v string) time.Duration {
	n, err := strconv.Atoi(strings.TrimSpace(v))
	if err != nil || n <= 0 {
		return time.Second
	}
	return min(time.Duration(n)*time.Second, maxRetryAfter)
}

// pending describes what waits to be sent, for a log line.
func (s *Shipper) pending() string {
	var files, docs int
	var size int64
	if s.spool != nil {
		files, size, docs = s.spool.Stats()
	}
	mf, ms, md := s.mem.Stats()
	return fmt.Sprintf("%d records in %d batches (%d KB) wait to be sent", docs+md, files+mf, (size+ms)>>10)
}

// Shutdown flushes the batch in hand to the spool, stops the sender and gives
// what is queued a few seconds to go; whatever remains in the spool is sent at
// the next start.
func (s *Shipper) Shutdown() {
	close(s.inCh)
	<-s.done
	close(s.stop)
	<-s.senderDone
	ctx, cancel := context.WithTimeout(context.Background(), shutdownGrace)
	defer cancel()
	if _, ok := s.drain(ctx); !ok {
		s.onError(s.pending() + "; the spool is sent at the next start")
	}
}

// memQueue holds batches in memory when the spool cannot be written: a bounded
// stand-in that keeps shipping working while Loom is up, oldest dropped first.
type memQueue struct {
	max    int64
	onDrop func(reason string, docs int)

	mu    sync.Mutex
	items []memItem
	total int64
	seq   uint64
}

type memItem struct {
	name string
	body []byte
	n    int
}

func (m *memQueue) Put(body []byte, n int) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.seq++
	m.items = append(m.items, memItem{name: strconv.FormatUint(m.seq, 10), body: body, n: n})
	m.total += int64(len(body))
	for m.total > m.max && len(m.items) > 1 {
		old := m.items[0]
		m.items = m.items[1:]
		m.total -= int64(len(old.body))
		m.onDrop("memory", old.n)
	}
}

func (m *memQueue) Oldest() (string, []byte, int, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.items) == 0 {
		return "", nil, 0, false
	}
	it := m.items[0]
	return it.name, it.body, it.n, true
}

func (m *memQueue) Remove(name string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for i, it := range m.items {
		if it.name == name {
			m.items = append(m.items[:i], m.items[i+1:]...)
			m.total -= int64(len(it.body))
			break
		}
	}
	return nil
}

func (m *memQueue) Split(name string, body []byte) (bool, error) {
	var docs []json.RawMessage
	if err := json.Unmarshal(body, &docs); err != nil {
		return false, err
	}
	if len(docs) < 2 {
		return false, nil
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	for i, it := range m.items {
		if it.name != name {
			continue
		}
		mid := len(docs) / 2
		a := memItem{name: name + "a", body: joinDocs(docs[:mid]), n: mid}
		b := memItem{name: name + "b", body: joinDocs(docs[mid:]), n: len(docs) - mid}
		rest := append([]memItem{}, m.items[i+1:]...)
		m.items = append(append(m.items[:i], a, b), rest...)
		m.total += int64(len(a.body)+len(b.body)) - int64(len(it.body))
		return true, nil
	}
	return true, nil
}

func (m *memQueue) Stats() (int, int64, int) {
	m.mu.Lock()
	defer m.mu.Unlock()
	docs := 0
	for _, it := range m.items {
		docs += it.n
	}
	return len(m.items), m.total, docs
}
