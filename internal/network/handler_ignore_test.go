package network

import (
	"net"
	"net/netip"
	"sync"
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

// A counter nobody checks is the same failure as no counter at all, so the
// accounting is tested rather than assumed.
func TestDropAccounting(t *testing.T) {
	h := &Handler{}
	h.SetIgnoredNets([]netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")})

	total, per := h.DropStats()
	if total != 0 || len(per) != 0 {
		t.Fatalf("a fresh handler must have dropped nothing, got %d %v", total, per)
	}

	for i := 0; i < 3; i++ {
		h.countDrop("10.0.0.1")
	}
	h.countDrop("10.0.0.2")

	total, per = h.DropStats()
	if total != 4 {
		t.Errorf("total = %d, want 4", total)
	}
	if per["10.0.0.1"] != 3 {
		t.Errorf("10.0.0.1 = %d, want 3", per["10.0.0.1"])
	}
	if per["10.0.0.2"] != 1 {
		t.Errorf("10.0.0.2 = %d, want 1", per["10.0.0.2"])
	}
}

// Concurrent accepts are the normal case, so the counters must survive them.
func TestDropAccountingIsConcurrencySafe(t *testing.T) {
	h := &Handler{}
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				h.countDrop("203.0.113.5")
			}
		}()
	}
	wg.Wait()
	total, per := h.DropStats()
	if total != 5000 || per["203.0.113.5"] != 5000 {
		t.Errorf("total=%d per=%d, want 5000 each", total, per["203.0.113.5"])
	}
}
