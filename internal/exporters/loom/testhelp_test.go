package loom

import (
	"encoding/json"
	"net/http"
	"testing"
)

func decodeJSON(t *testing.T, r *http.Request, v interface{}) {
	t.Helper()
	if err := json.NewDecoder(r.Body).Decode(v); err != nil {
		t.Fatalf("decode request body: %v", err)
	}
}
