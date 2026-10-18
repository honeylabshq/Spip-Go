package loom

import (
	"encoding/json"
	"net"
	"net/http"
	"sync"
	"testing"
	"time"

	"spip/internal/config"
)

func TestShipperBatchesAndFlushes(t *testing.T) {
	var received [][]map[string]interface{}
	var mu sync.Mutex
	srv := http.Server{
		Addr: "127.0.0.1:0",
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodPost {
				t.Errorf("unexpected method %s", r.Method)
				return
			}
			var batch []map[string]interface{}
			if err := json.NewDecoder(r.Body).Decode(&batch); err != nil {
				t.Errorf("decode: %v", err)
				return
			}
			mu.Lock()
			received = append(received, batch)
			mu.Unlock()
			w.WriteHeader(http.StatusOK)
		}),
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	go srv.Serve(ln)
	defer srv.Close()

	url := "http://" + ln.Addr().String()
	fullCfg := config.Config{
		Name: "x", IP: "127.0.0.1", Port: 8080,
		Loom: config.LoomConfig{
			Enabled:       true,
			URL:           url,
			SensorID:      "test-sensor",
			Token:         "test-token",
			BatchSize:     2,
			FlushInterval: "100ms",
			SpoolDir:      t.TempDir(),
		},
	}
	if err := fullCfg.Validate(); err != nil {
		t.Fatalf("validate: %v", err)
	}

	var errs []string
	onError := func(msg string) { errs = append(errs, msg) }
	shipper := NewShipper(&fullCfg.Loom, onError)
	inCh, _ := shipper.Run()

	inCh <- map[string]interface{}{"event": "a"}
	inCh <- map[string]interface{}{"event": "b"}
	time.Sleep(150 * time.Millisecond)

	mu.Lock()
	n := len(received)
	mu.Unlock()
	if n < 1 {
		t.Fatalf("expected at least one batch, got %d", n)
	}
	if len(received[0]) != 2 {
		t.Errorf("expected batch size 2, got %d", len(received[0]))
	}

	shipper.Shutdown()

	if len(errs) > 0 {
		t.Errorf("unexpected errors: %v", errs)
	}
}
