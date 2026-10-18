package loom

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"spip/internal/config"
)

// collector stands in for Loom. respond picks the status for each request;
// only 2xx requests count as delivered.
type collector struct {
	srv     *httptest.Server
	mu      sync.Mutex
	bodies  [][]byte
	ids     map[string]int
	calls   atomic.Int32
	respond func(body []byte) int
}

func newCollector(t *testing.T, respond func([]byte) int) *collector {
	t.Helper()
	c := &collector{ids: map[string]int{}, respond: respond}
	c.srv = httptest.NewServer(c)
	t.Cleanup(c.srv.Close)
	return c
}

func (c *collector) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	c.calls.Add(1)
	body, _ := io.ReadAll(r.Body)
	status := http.StatusOK
	if c.respond != nil {
		status = c.respond(body)
	}
	if status >= 200 && status < 300 {
		var docs []map[string]interface{}
		if err := json.Unmarshal(body, &docs); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		c.mu.Lock()
		c.bodies = append(c.bodies, body)
		for _, d := range docs {
			c.ids[fmt.Sprint(d["id"])]++
		}
		c.mu.Unlock()
	}
	if status == http.StatusTooManyRequests {
		w.Header().Set("Retry-After", "0")
	}
	w.WriteHeader(status)
}

func (c *collector) delivered() (distinct, total int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, n := range c.ids {
		total += n
	}
	return len(c.ids), total
}

func (c *collector) duplicates() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	var out []string
	for id, n := range c.ids {
		if n != 1 {
			out = append(out, fmt.Sprintf("%s x%d", id, n))
		}
	}
	return out
}

type errLog struct {
	mu   sync.Mutex
	msgs []string
}

func (l *errLog) add(m string) { l.mu.Lock(); l.msgs = append(l.msgs, m); l.mu.Unlock() }

func (l *errLog) all() []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]string{}, l.msgs...)
}

func newTestShipper(t *testing.T, url, dir string, batchSize int) (*Shipper, chan<- map[string]interface{}, *errLog) {
	t.Helper()
	if dir == "" {
		dir = t.TempDir()
	}
	cfg := config.Config{Name: "x", IP: "127.0.0.1", Port: 8080, Loom: config.LoomConfig{
		Enabled: true, URL: url, SensorID: "test", Token: "t",
		BatchSize: batchSize, FlushInterval: "20ms", SpoolDir: dir,
	}}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	lg := &errLog{}
	s := NewShipper(&cfg.Loom, lg.add)
	s.backoff, s.maxBackoff = 5*time.Millisecond, 40*time.Millisecond
	ch, _ := s.Run()
	return s, ch, lg
}

func ev(i int) map[string]interface{} { return map[string]interface{}{"id": fmt.Sprint(i)} }

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

// The bytes on the wire are what json.Marshal of the whole batch produced
// before the spool: Spip's records feed a fixed ClickHouse schema and must
// not change by a byte.
func TestWireBytesMatchTheOldEncoding(t *testing.T) {
	c := newCollector(t, nil)
	s, ch, _ := newTestShipper(t, c.srv.URL, "", 3)
	batch := []map[string]interface{}{
		{"id": "1", "event": map[string]interface{}{"original": "GET /<script>&x HTTP/1.1\r\n", "n": 1.5}},
		{"id": "2", "user_agent": map[string]interface{}{"original": "é   \x01"}, "ports": []interface{}{80, 443}},
		{"id": "3", "@timestamp": "2026-10-18T13:52:00.123Z", "z": nil, "a": true},
	}
	for _, d := range batch {
		ch <- d
	}
	waitFor(t, "the batch", func() bool { _, n := c.delivered(); return n == 3 })
	s.Shutdown()
	want, _ := json.Marshal(batch)
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.bodies) != 1 || !bytes.Equal(c.bodies[0], want) {
		t.Fatalf("wire body\n%s\nwant\n%s", c.bodies, want)
	}
}

// Loom answers 503 for a while and then recovers. Every record sent during
// the outage arrives once, and so does every record sent after it.
func TestOutage503ThenRecoveryDeliversEverythingOnce(t *testing.T) {
	var down atomic.Bool
	down.Store(true)
	c := newCollector(t, func([]byte) int {
		if down.Load() {
			return http.StatusServiceUnavailable
		}
		return http.StatusOK
	})
	s, ch, _ := newTestShipper(t, c.srv.URL, "", 7)
	for i := 0; i < 300; i++ {
		ch <- ev(i)
	}
	time.Sleep(150 * time.Millisecond)
	if _, n := c.delivered(); n != 0 {
		t.Fatalf("%d records delivered while Loom was down", n)
	}
	down.Store(false)
	for i := 300; i < 400; i++ {
		ch <- ev(i)
	}
	waitFor(t, "every record", func() bool { d, _ := c.delivered(); return d == 400 })
	s.Shutdown()
	if d, n := c.delivered(); d != 400 || n != 400 {
		t.Fatalf("delivered %d distinct, %d total; want 400 each (duplicates: %v)", d, n, c.duplicates())
	}
	if files, _, _ := s.spool.Stats(); files != 0 {
		t.Fatalf("spool still holds %d batches", files)
	}
}

// Loom's port is closed (connection refused) during the outage, then a
// server comes up on it.
func TestOutageRefusedThenRecoveryDeliversEverythingOnce(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	ln.Close()

	s, ch, lg := newTestShipper(t, "http://"+addr, "", 10)
	for i := 0; i < 250; i++ {
		ch <- ev(i)
	}
	waitFor(t, "a refused post", func() bool { return len(lg.all()) > 0 })

	ln, err = net.Listen("tcp", addr)
	if err != nil {
		t.Skipf("could not rebind %s: %v", addr, err)
	}
	c := &collector{ids: map[string]int{}}
	srv := &http.Server{Handler: c}
	go srv.Serve(ln)
	defer srv.Close()
	for i := 250; i < 300; i++ {
		ch <- ev(i)
	}
	waitFor(t, "every record", func() bool { d, _ := c.delivered(); return d == 300 })
	s.Shutdown()
	if d, n := c.delivered(); d != 300 || n != 300 {
		t.Fatalf("delivered %d distinct, %d total; want 300 each (duplicates: %v)", d, n, c.duplicates())
	}
}

// Capture hands records to the channel without waiting; a Loom that hangs on
// every request must not back that channel up.
func TestHungLoomNeverBlocksTheChannel(t *testing.T) {
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-release
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	defer close(release)
	s, ch, _ := newTestShipper(t, srv.URL, "", 50)
	s.client.Timeout = time.Hour

	start := time.Now()
	for i := 0; i < 5000; i++ {
		select {
		case ch <- ev(i):
		case <-time.After(5 * time.Second):
			t.Fatalf("channel blocked at record %d with Loom hung", i)
		}
	}
	waitFor(t, "the spool to take every record", func() bool {
		_, _, docs := s.spool.Stats()
		return docs >= 4950 // the one in flight is still counted; the batch in hand may not be flushed yet
	})
	if d := time.Since(start); d > 8*time.Second {
		t.Fatalf("5000 records took %v to queue", d)
	}
}

// A sensor restarted during an outage sends what it spooled before.
func TestSpoolSurvivesARestart(t *testing.T) {
	dir := t.TempDir()
	dead := newCollector(t, func([]byte) int { return http.StatusBadGateway })
	s, ch, _ := newTestShipper(t, dead.srv.URL, dir, 10)
	for i := 0; i < 95; i++ {
		ch <- ev(i)
	}
	s.Shutdown()
	if _, _, docs := s.spool.Stats(); docs != 95 {
		t.Fatalf("spool holds %d records at shutdown, want 95", docs)
	}

	c := newCollector(t, nil)
	s2, _, _ := newTestShipper(t, c.srv.URL, dir, 10)
	waitFor(t, "the spooled records", func() bool { d, _ := c.delivered(); return d == 95 })
	s2.Shutdown()
	if d, n := c.delivered(); d != 95 || n != 95 {
		t.Fatalf("delivered %d distinct, %d total; want 95 each", d, n)
	}
}

// After a 2xx nothing is sent again, also not after a restart.
func TestNoResendAfter2xx(t *testing.T) {
	dir := t.TempDir()
	c := newCollector(t, nil)
	s, ch, _ := newTestShipper(t, c.srv.URL, dir, 5)
	for i := 0; i < 20; i++ {
		ch <- ev(i)
	}
	waitFor(t, "delivery", func() bool { _, n := c.delivered(); return n == 20 })
	s.Shutdown()
	calls := c.calls.Load()

	s2, _, _ := newTestShipper(t, c.srv.URL, dir, 5)
	time.Sleep(100 * time.Millisecond)
	s2.Shutdown()
	if got := c.calls.Load(); got != calls {
		t.Fatalf("restart sent %d more requests after everything was delivered", got-calls)
	}
	entries, _ := os.ReadDir(dir)
	if len(entries) != 0 {
		t.Fatalf("spool dir holds %d files after delivery", len(entries))
	}
}

// Over Loom's body limit the batch is halved until each part fits, and every
// record arrives once.
func Test413SplitsUntilBatchesFit(t *testing.T) {
	c := newCollector(t, func(body []byte) int {
		var docs []json.RawMessage
		_ = json.Unmarshal(body, &docs)
		if len(docs) > 2 {
			return http.StatusRequestEntityTooLarge
		}
		return http.StatusOK
	})
	s, ch, _ := newTestShipper(t, c.srv.URL, "", 9)
	for i := 0; i < 9; i++ {
		ch <- ev(i)
	}
	waitFor(t, "every record", func() bool { d, _ := c.delivered(); return d == 9 })
	s.Shutdown()
	if d, n := c.delivered(); d != 9 || n != 9 {
		t.Fatalf("delivered %d distinct, %d total; want 9 each", d, n)
	}
}

// A single record Loom refuses as too large is dropped, and what follows it
// still arrives.
func Test413OnASingleRecordDropsOnlyIt(t *testing.T) {
	c := newCollector(t, func(body []byte) int {
		if bytes.Contains(body, []byte(`"id":"big"`)) {
			return http.StatusRequestEntityTooLarge
		}
		return http.StatusOK
	})
	s, ch, lg := newTestShipper(t, c.srv.URL, "", 4)
	ch <- map[string]interface{}{"id": "big"}
	for i := 0; i < 7; i++ {
		ch <- ev(i)
	}
	waitFor(t, "the other records", func() bool { d, _ := c.delivered(); return d == 7 })
	s.Shutdown()
	found := false
	for _, m := range lg.all() {
		if bytes.Contains([]byte(m), []byte("too large")) {
			found = true
		}
	}
	if !found {
		t.Fatalf("the drop was not logged: %v", lg.all())
	}
}

// A token Loom does not know is kept and retried, so fixing it on either side
// delivers what waited.
func Test401IsRetriedUntilTheTokenWorks(t *testing.T) {
	var ok atomic.Bool
	c := newCollector(t, func([]byte) int {
		if ok.Load() {
			return http.StatusOK
		}
		return http.StatusUnauthorized
	})
	s, ch, lg := newTestShipper(t, c.srv.URL, "", 1)
	ch <- ev(1)
	waitFor(t, "retries", func() bool { return c.calls.Load() >= 3 })
	if len(lg.all()) == 0 {
		t.Fatal("the refusal was not logged")
	}
	ok.Store(true)
	waitFor(t, "delivery", func() bool { d, _ := c.delivered(); return d == 1 })
	s.Shutdown()
}

func Test400DropsTheBatch(t *testing.T) {
	c := newCollector(t, func(body []byte) int {
		if bytes.Contains(body, []byte(`"id":"bad"`)) {
			return http.StatusBadRequest
		}
		return http.StatusOK
	})
	s, ch, _ := newTestShipper(t, c.srv.URL, "", 1)
	ch <- map[string]interface{}{"id": "bad"}
	ch <- ev(2)
	waitFor(t, "the next record", func() bool { d, _ := c.delivered(); return d == 1 })
	s.Shutdown()
	if files, _, _ := s.spool.Stats(); files != 0 {
		t.Fatalf("the refused batch is still spooled")
	}
}

func Test429IsRetried(t *testing.T) {
	var n atomic.Int32
	c := newCollector(t, func([]byte) int {
		if n.Add(1) == 1 {
			return http.StatusTooManyRequests
		}
		return http.StatusOK
	})
	s, ch, _ := newTestShipper(t, c.srv.URL, "", 1)
	ch <- ev(1)
	waitFor(t, "delivery", func() bool { d, _ := c.delivered(); return d == 1 })
	s.Shutdown()
}

// With no usable spool directory at all, batches wait in memory and still
// reach Loom.
func TestUnusableSpoolFallsBackToMemory(t *testing.T) {
	c := newCollector(t, nil)
	notDir := t.TempDir() + "/file"
	if err := os.WriteFile(notDir, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := &config.LoomConfig{URL: c.srv.URL, SensorID: "s", Token: "t", BatchSize: 2, SpoolDir: notDir + "/spool"}
	defer func(old string) { fallbackSpoolDir = old }(fallbackSpoolDir)
	fallbackSpoolDir = notDir + "/fallback"
	lg := &errLog{}
	s := NewShipper(cfg, lg.add)
	if s.spool != nil {
		t.Fatal("a spool opened under a regular file")
	}
	ch, _ := s.Run()
	ch <- ev(1)
	ch <- ev(2)
	waitFor(t, "delivery", func() bool { d, _ := c.delivered(); return d == 2 })
	s.Shutdown()
	if len(lg.all()) == 0 {
		t.Fatal("the unusable spool directory was not logged")
	}
}

func TestParseRetryAfter(t *testing.T) {
	for in, want := range map[string]time.Duration{"": time.Second, "3": 3 * time.Second, "999": maxRetryAfter, "Wed, 21 Oct 2015 07:28:00 GMT": time.Second} {
		if got := parseRetryAfter(in); got != want {
			t.Errorf("parseRetryAfter(%q) = %v, want %v", in, got, want)
		}
	}
}
