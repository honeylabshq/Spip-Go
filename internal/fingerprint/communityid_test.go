package fingerprint

import (
	"testing"
)

func TestCommunityIDV1(t *testing.T) {
	// Example from Community ID spec: same flow in either direction gives same hash
	id1 := CommunityIDV1("192.168.1.1", "192.168.1.2", 12345, 443, 6, 0)
	id2 := CommunityIDV1("192.168.1.2", "192.168.1.1", 443, 12345, 6, 0)
	if id1 == "" || id2 == "" {
		t.Fatalf("empty community id")
	}
	if id1 != id2 {
		t.Errorf("normalized flow should match: %q != %q", id1, id2)
	}
	if id1[:2] != "1:" {
		t.Errorf("expected prefix 1: got %q", id1[:2])
	}
}

func TestCommunityIDV1_InvalidIP(t *testing.T) {
	if got := CommunityIDV1("invalid", "192.168.1.2", 80, 443, 6, 0); got != "" {
		t.Errorf("expected empty for invalid IP, got %q", got)
	}
}
