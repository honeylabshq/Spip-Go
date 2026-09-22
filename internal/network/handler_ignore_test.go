package network

import (
	"net"
	"net/netip"
	"testing"
)

// The handler holds its own copy of the drop list, so it is tested here as
// well as in config: a mismatch between the two is the failure that would let
// traffic through while the config looks right.
func TestHandlerShouldIgnore(t *testing.T) {
	h := &Handler{}
	if h.shouldIgnore(net.ParseIP("185.228.82.243")) {
		t.Fatal("an empty list must drop nothing")
	}

	h.SetIgnoredNets([]netip.Prefix{
		netip.MustParsePrefix("185.228.82.243/32"),
		netip.MustParsePrefix("10.0.0.0/8"),
	})

	cases := map[string]bool{
		"185.228.82.243": true,
		"185.228.82.242": false,
		"10.255.255.254": true,
		"11.0.0.1":       false,
		"8.8.8.8":        false,
	}
	for ip, want := range cases {
		if got := h.shouldIgnore(net.ParseIP(ip)); got != want {
			t.Errorf("shouldIgnore(%s) = %v, want %v", ip, got, want)
		}
	}

	// net.ParseIP returns 16-byte v4-mapped values; the check must still match.
	if !h.shouldIgnore(net.ParseIP("185.228.82.243").To16()) {
		t.Error("a v4-mapped address of a listed host must be dropped")
	}
}
