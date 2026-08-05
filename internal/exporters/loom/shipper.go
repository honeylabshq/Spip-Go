package loom

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"spip/internal/config"
)

const (
	channelCapacity = 256
	clientTimeout   = 15 * time.Second
)

type Shipper struct {
	cfg     *config.LoomConfig
	client  *http.Client
	inCh    chan map[string]interface{}
	done    chan struct{}
	onError func(string)
}

func NewShipper(cfg *config.LoomConfig, onError func(string)) *Shipper {
	var transport http.RoundTripper = http.DefaultTransport
	if cfg.InsecureSkipVerify {
		transport = &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}
	}
	client := &http.Client{Timeout: clientTimeout, Transport: transport}
	return &Shipper{
		cfg:     cfg,
		client:  client,
		inCh:    make(chan map[string]interface{}, channelCapacity),
		done:    make(chan struct{}),
		onError: onError,
	}
}

// maxSendAttempts and maxSplitDepth bound the work a single flush can cause.
// Three attempts covers a Loom restart or a brief network blip; a deeper retry
// would queue events behind a genuinely dead collector instead of shedding.
const (
	maxSendAttempts = 3
	maxSplitDepth   = 4
)

// send delivers one batch, retrying what is worth retrying.
//
// Previously every failure path ended in `batch = nil`: a transport error, a
// 500, or a 413 all silently discarded up to batch_size events, and a Loom
// restart lost whatever was in flight. This is the only hop in the pipeline
// without an at-least-once story (Loom keeps a durable outbox for its own
// writes to ClickHouse), so a retry here is what makes the chain whole.
//
// The three cases are deliberately different:
//
//	413            the batch is too large for Loom's max_body_size_bytes, and
//	               retrying it unchanged would fail forever. Split in half and
//	               send each part; a single oversized event eventually lands
//	               alone and is dropped with a clear message rather than
//	               poisoning everything batched alongside it.
//	5xx, transport transient. Back off and retry.
//	4xx other      a bad token or a malformed body cannot succeed on retry, so
//	               drop immediately rather than spend attempts on it.
func (s *Shipper) send(batch []map[string]interface{}, depth int) {
	if len(batch) == 0 {
		return
	}
	body, err := json.Marshal(batch)
	if err != nil {
		s.onError(fmt.Sprintf("loom marshal: %v", err))
		return
	}

	for attempt := 0; attempt < maxSendAttempts; attempt++ {
		if attempt > 0 {
			time.Sleep(time.Duration(1<<uint(attempt-1)) * time.Second)
		}

		req, err := http.NewRequest(http.MethodPost, s.cfg.URL, bytes.NewReader(body))
		if err != nil {
			s.onError(fmt.Sprintf("loom request: %v", err))
			return
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Spip-ID", s.cfg.SensorID)
		req.Header.Set("Authorization", "Bearer "+s.cfg.Token)

		resp, err := s.client.Do(req)
		if err != nil {
			s.onError(fmt.Sprintf("loom POST: %v (attempt %d/%d)", err, attempt+1, maxSendAttempts))
			continue
		}
		status := resp.StatusCode
		resp.Body.Close()

		switch {
		case status >= 200 && status < 300:
			return

		case status == http.StatusRequestEntityTooLarge:
			if len(batch) == 1 {
				s.onError(fmt.Sprintf("loom POST: single event exceeds Loom's body limit, dropped (%d bytes)", len(body)))
				return
			}
			if depth >= maxSplitDepth {
				s.onError(fmt.Sprintf("loom POST: 413 still after %d splits, dropping %d events", depth, len(batch)))
				return
			}
			mid := len(batch) / 2
			s.send(batch[:mid], depth+1)
			s.send(batch[mid:], depth+1)
			return

		case status >= 500:
			s.onError(fmt.Sprintf("loom POST: status %d (attempt %d/%d)", status, attempt+1, maxSendAttempts))
			continue

		default:
			// 4xx other than 413: a rejected token or a malformed body. Retrying
			// cannot help, and hiding it behind retries would delay the log line
			// that explains why nothing is arriving.
			s.onError(fmt.Sprintf("loom POST: status %d, dropping %d events", status, len(batch)))
			return
		}
	}
	s.onError(fmt.Sprintf("loom POST: giving up after %d attempts, dropping %d events", maxSendAttempts, len(batch)))
}

func (s *Shipper) Run() (chan<- map[string]interface{}, <-chan struct{}) {
	var batch []map[string]interface{}
	flush := func() {
		if len(batch) == 0 {
			return
		}
		s.send(batch, 0)
		batch = nil
	}

	go func() {
		defer close(s.done)
		ticker := time.NewTicker(s.cfg.FlushIntervalDuration())
		defer ticker.Stop()
		for {
			select {
			case ev, ok := <-s.inCh:
				if !ok {
					flush()
					return
				}
				batch = append(batch, ev)
				if len(batch) >= s.cfg.BatchSize {
					flush()
				}
			case <-ticker.C:
				flush()
			}
		}
	}()

	return s.inCh, s.done
}

func (s *Shipper) Shutdown() {
	close(s.inCh)
	<-s.done
}
