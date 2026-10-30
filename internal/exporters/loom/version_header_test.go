package loom

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"spip/internal/config"
)

// The build version rides in a request header and nowhere else: the records
// Loom receives must be byte-for-byte what they were before the header.
func TestPostSendsVersionHeaderOnly(t *testing.T) {
	type got struct {
		header string
		has    bool
		body   []byte
	}
	for _, tc := range []struct {
		name    string
		version string
	}{
		{"with a version", "v1.4.0-12-g3d9d463"},
		{"without a version", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			seen := make(chan got, 1)
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				b, _ := io.ReadAll(r.Body)
				_, has := r.Header[http.CanonicalHeaderKey(versionHeader)]
				select {
				case seen <- got{r.Header.Get(versionHeader), has, b}:
				default:
				}
				w.WriteHeader(http.StatusNoContent)
			}))
			defer srv.Close()

			old := Version
			Version = tc.version
			defer func() { Version = old }()

			s := NewShipper(&config.LoomConfig{URL: srv.URL, SensorID: "spip-test", Token: "t"}, func(string) {})
			body, _ := json.Marshal([]map[string]any{{"event": map[string]any{"id": "a"}}})
			status, _, err := s.post(t.Context(), body)
			if err != nil || status != http.StatusNoContent {
				t.Fatalf("post: %d %v", status, err)
			}
			var g got
			select {
			case g = <-seen:
			case <-time.After(5 * time.Second):
				t.Fatal("server saw no request")
			}
			if tc.version == "" && g.has {
				t.Fatalf("an empty version sent the header %q", g.header)
			}
			if tc.version != "" && g.header != tc.version {
				t.Fatalf("header %q, want %q", g.header, tc.version)
			}
			if string(g.body) != string(body) {
				t.Fatalf("body changed: %s", g.body)
			}
		})
	}
}
