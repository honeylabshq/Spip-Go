package fingerprint

import (
	"testing"
)

func TestHTTPFP(t *testing.T) {
	// GET, HTTP/1.1, no cookie, no referer, 1 header (Host), no Accept-Language
	got := HTTPFP("GET", "HTTP/1.1", []string{"Host"}, false, false, "")
	if got == "" {
		t.Fatal("expected a non-empty HTTP request fingerprint")
	}
	// Format: method(2) + version(2) + cookie(1) + referer(1) + count(2) + lang(2) + _ + 12 hex
	if len(got) < 12 {
		t.Errorf("HTTP request fingerprint too short: %q", got)
	}
}

func TestHTTPFP_Method2Chars(t *testing.T) {
	for method, want := range map[string]string{
		"GET": "ge", "POST": "po", "PUT": "pu", "DELETE": "de",
		"HEAD": "he", "OPTIONS": "op", "PATCH": "pa",
	} {
		got := HTTPFP(method, "HTTP/1.1", nil, false, false, "")
		if len(got) >= 2 && got[:2] != want {
			t.Errorf("method %s: expected prefix %s, got %q", method, want, got[:2])
		}
	}
}
