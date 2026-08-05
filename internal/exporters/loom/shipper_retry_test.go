package loom

import (
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"

	"spip/internal/config"
)

// The shipper used to end every failure path in `batch = nil`, so a transport
// error, a 500 or a 413 silently discarded up to batch_size events and a Loom
// restart lost whatever was in flight. These pin the three behaviours that
// replaced that.

func newTestShipper(t *testing.T, url string) (*Shipper, *[]string) {
	t.Helper()
	var mu sync.Mutex
	errs := []string{}
	s := NewShipper(&config.LoomConfig{URL: url, SensorID: "test", Token: "t"},
		func(m string) { mu.Lock(); errs = append(errs, m); mu.Unlock() })
	return s, &errs
}

func ev(i int) map[string]interface{} { return map[string]interface{}{"n": i} }

func TestSend_RetriesOn5xxThenSucceeds(t *testing.T) {
	var calls int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if atomic.AddInt32(&calls, 1) < 3 {
			w.WriteHeader(http.StatusBadGateway)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	s, _ := newTestShipper(t, srv.URL)
	s.send([]map[string]interface{}{ev(1), ev(2)}, 0)

	if got := atomic.LoadInt32(&calls); got != 3 {
		t.Fatalf("expected 3 attempts (two 502s then a 200), got %d", got)
	}
}

func TestSend_SplitsOn413UntilBatchesFit(t *testing.T) {
	// Accept at most 2 events per request; anything larger is 413. A batch of 8
	// must therefore be split down and delivered in full rather than dropped.
	var mu sync.Mutex
	delivered := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body []map[string]interface{}
		decodeJSON(t, r, &body)
		if len(body) > 2 {
			w.WriteHeader(http.StatusRequestEntityTooLarge)
			return
		}
		mu.Lock()
		delivered += len(body)
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	s, _ := newTestShipper(t, srv.URL)
	batch := make([]map[string]interface{}, 8)
	for i := range batch {
		batch[i] = ev(i)
	}
	s.send(batch, 0)

	mu.Lock()
	defer mu.Unlock()
	if delivered != 8 {
		t.Fatalf("expected all 8 events delivered after splitting, got %d", delivered)
	}
}

func TestSend_DoesNotRetryOn401(t *testing.T) {
	var calls int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&calls, 1)
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()

	s, errs := newTestShipper(t, srv.URL)
	s.send([]map[string]interface{}{ev(1)}, 0)

	if got := atomic.LoadInt32(&calls); got != 1 {
		t.Fatalf("a rejected token cannot succeed on retry; expected 1 attempt, got %d", got)
	}
	if len(*errs) == 0 {
		t.Fatal("expected the drop to be reported, so the operator can see why nothing arrives")
	}
}
