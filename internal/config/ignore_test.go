package config

import (
	"net/netip"
	"os"
	"path/filepath"
	"testing"
)

func writeConfig(t *testing.T, body string) string {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, "config.toml")
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}
	return p
}

// A typo in this list means traffic an operator believes is dropped is being
// recorded, so an unparsable entry must fail the load rather than be skipped.
func TestIgnoreSourcesRejectsBadEntries(t *testing.T) {
	for _, bad := range []string{"not-an-ip", "192.0.2.1/33", "192.0.2.0/", "300.1.2.3"} {
		p := writeConfig(t, "name=\"t\"\nip=\"127.0.0.1\"\nport=8080\nignore_sources=[\""+bad+"\"]\n")
		if _, err := LoadConfig(p); err == nil {
			t.Errorf("LoadConfig accepted %q, want an error", bad)
		}
	}
}

func TestShouldIgnore(t *testing.T) {
	p := writeConfig(t, `
name = "t"
ip = "127.0.0.1"
port = 8080
ignore_sources = ["185.228.82.243", "10.0.0.0/8", "2001:db8::/32"]
`)
	c, err := LoadConfig(p)
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}

	cases := []struct {
		addr string
		want bool
	}{
		{"185.228.82.243", true},  // the exact host
		{"185.228.82.244", false}, // its neighbour must not be caught
		{"10.1.2.3", true},        // inside the v4 network
		{"11.1.2.3", false},
		{"2001:db8::1", true}, // inside the v6 network
		{"2001:db9::1", false},
		{"::ffff:185.228.82.243", true}, // v4-mapped form of a listed host
		{"::ffff:10.1.2.3", true},
		{"8.8.8.8", false},
	}
	for _, c2 := range cases {
		a, err := netip.ParseAddr(c2.addr)
		if err != nil {
			t.Fatalf("parse %s: %v", c2.addr, err)
		}
		if got := c.ShouldIgnore(a); got != c2.want {
			t.Errorf("ShouldIgnore(%s) = %v, want %v", c2.addr, got, c2.want)
		}
	}
}

// With nothing configured a honeypot must record everything, which is the
// whole point of it.
func TestNoIgnoreListRecordsEverything(t *testing.T) {
	p := writeConfig(t, "name=\"t\"\nip=\"127.0.0.1\"\nport=8080\n")
	c, err := LoadConfig(p)
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	if len(c.IgnoredNets()) != 0 {
		t.Fatalf("expected an empty ignore list, got %v", c.IgnoredNets())
	}
	a := netip.MustParseAddr("185.228.82.243")
	if c.ShouldIgnore(a) {
		t.Error("an unconfigured sensor must not drop anything")
	}
}
