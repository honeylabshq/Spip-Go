package udp

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"spip/internal/logging"
	"spip/pkg/conntrack"
	"spip/pkg/socket"
)

type fakeConntrack struct {
	mu     sync.Mutex
	asked  []netip.AddrPort
	answer netip.AddrPort
	err    error
}

func (f *fakeConntrack) OriginalDst(proto uint8, remote, local netip.AddrPort) (netip.AddrPort, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.asked = append(f.asked, remote, local)
	return f.answer, f.err
}

type lockedBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *lockedBuffer) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

func (l *lockedBuffer) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.String()
}

func TestRedirectedLookupUsesTheReplyTuple(t *testing.T) {
	ct := &fakeConntrack{answer: netip.MustParseAddrPort("192.0.2.1:53")}
	s := NewServer(logging.NewLogger(&bytes.Buffer{}), Options{Conntrack: ct})
	got := s.redirected(&net.UDPAddr{IP: net.ParseIP("198.51.100.7"), Port: 40000},
		&socket.OriginalDst{IP: net.ParseIP("192.0.2.1"), Port: 8080}, time.Now())
	if got.Port != 53 || !got.IP.Equal(net.ParseIP("192.0.2.1")) {
		t.Fatalf("got %v:%d", got.IP, got.Port)
	}
	want := []netip.AddrPort{netip.MustParseAddrPort("198.51.100.7:40000"), netip.MustParseAddrPort("192.0.2.1:8080")}
	if len(ct.asked) != 2 || ct.asked[0] != want[0] || ct.asked[1] != want[1] {
		t.Fatalf("asked %v, want %v", ct.asked, want)
	}
	if s.ctResolved.Load() != 1 {
		t.Fatal("resolution not counted")
	}
}

func TestRedirectedLookupFailureKeepsTheListenerPort(t *testing.T) {
	ct := &fakeConntrack{err: errors.New("no conntrack entry")}
	s := NewServer(logging.NewLogger(&bytes.Buffer{}), Options{Conntrack: ct})
	dst := &socket.OriginalDst{IP: net.ParseIP("192.0.2.1"), Port: 8080}
	if got := s.redirected(&net.UDPAddr{IP: net.ParseIP("198.51.100.7"), Port: 1}, dst, time.Now()); got != dst {
		t.Fatalf("got %v", got)
	}
	if s.ctMissing.Load() != 1 {
		t.Fatal("miss not counted")
	}
}

// Through a real socket: a datagram addressed to the listener's own port is
// resolved through conntrack, and the record carries the original port.
func TestServeResolvesListenerAddressedDatagrams(t *testing.T) {
	l, err := socket.ListenUDP("udp4", "127.0.0.1:0")
	if err != nil {
		t.Skipf("udp listen: %v", err)
	}
	out := &lockedBuffer{}
	ct := &fakeConntrack{answer: netip.MustParseAddrPort("127.0.0.1:161")}
	s := NewServer(logging.NewLogger(out), Options{Name: "spip-test", Conntrack: ct})
	done := make(chan error, 1)
	go func() { done <- s.Serve(l.Conn) }()

	c, err := net.DialUDP("udp4", nil, l.Conn.LocalAddr().(*net.UDPAddr))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if _, err := c.Write([]byte("0&\x02\x01\x01\x04\x06public")); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(3 * time.Second)
	for !strings.Contains(out.String(), `"destination"`) && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	l.Conn.Close()
	<-done
	s.Shutdown()

	var rec map[string]any
	for _, line := range strings.Split(out.String(), "\n") {
		if strings.Contains(line, `"destination"`) {
			if err := json.Unmarshal([]byte(line), &rec); err != nil {
				t.Fatal(err)
			}
		}
	}
	if rec == nil {
		t.Fatalf("no record written: %s", out.String())
	}
	if port := get(rec, "destination.port"); port != float64(161) {
		t.Fatalf("destination.port = %v, want 161", port)
	}
}

func (f *fakeConntrack) calls() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.asked) / 2
}

func listenerAddressed(s *Server, n int) {
	for i := 0; i < n; i++ {
		s.HandleDatagram([]byte("probe"),
			&net.UDPAddr{IP: net.ParseIP("198.51.100.7"), Port: 40000 + i},
			&socket.OriginalDst{IP: net.ParseIP("192.0.2.1"), Port: 8080})
	}
}

// The lookup costs a netlink round trip, so it must come after every check
// that can drop a datagram: a flood is limited first and resolved second.
func TestDroppedAndLimitedDatagramsNeverReachConntrack(t *testing.T) {
	ct := &fakeConntrack{answer: netip.MustParseAddrPort("192.0.2.1:53")}
	s := NewServer(logging.NewLogger(&bytes.Buffer{}), Options{
		Conntrack:  ct,
		IgnoreNets: []netip.Prefix{netip.MustParsePrefix("198.51.100.7/32")},
	})
	s.listenPort.Store(8080)
	listenerAddressed(s, 5)
	if ct.calls() != 0 {
		t.Fatalf("ignored source caused %d lookups", ct.calls())
	}

	s = NewServer(logging.NewLogger(&bytes.Buffer{}), Options{
		Conntrack: ct, RatePerSecond: 0.001, Burst: 2, SourceRate: 1000, SourceBurst: 1000,
	})
	s.listenPort.Store(8080)
	listenerAddressed(s, 50)
	if ct.calls() != 2 {
		t.Fatalf("%d lookups for a burst of 2", ct.calls())
	}
}

func TestDatagramsToOtherPortsAreNotLookedUp(t *testing.T) {
	ct := &fakeConntrack{answer: netip.MustParseAddrPort("192.0.2.1:53")}
	s := NewServer(logging.NewLogger(&bytes.Buffer{}), Options{Conntrack: ct})
	s.listenPort.Store(8080)
	s.HandleDatagram([]byte("probe"), &net.UDPAddr{IP: net.ParseIP("198.51.100.7"), Port: 1},
		&socket.OriginalDst{IP: net.ParseIP("192.0.2.1"), Port: 161})
	if ct.calls() != 0 {
		t.Fatal("TPROXY-delivered datagram was looked up")
	}
}

func TestBreakerPausesLookupsAfterRepeatedFailures(t *testing.T) {
	ct := &fakeConntrack{err: fmt.Errorf("netlink receive: %w", errors.New("resource temporarily unavailable"))}
	s := NewServer(logging.NewLogger(&bytes.Buffer{}), Options{Conntrack: ct})
	src := &net.UDPAddr{IP: net.ParseIP("198.51.100.7"), Port: 1}
	dst := &socket.OriginalDst{IP: net.ParseIP("192.0.2.1"), Port: 8080}
	t0 := time.Unix(1_800_000_000, 0)
	for i := 0; i < 10; i++ {
		s.redirected(src, dst, t0)
	}
	if ct.calls() != ctFailuresBeforePause || s.ctPaused.Load() != 10-ctFailuresBeforePause {
		t.Fatalf("calls %d, paused %d", ct.calls(), s.ctPaused.Load())
	}
	s.redirected(src, dst, t0.Add(ctPause))
	if ct.calls() != ctFailuresBeforePause+1 {
		t.Fatal("lookups did not resume after the pause")
	}
}

func TestMissingEntriesDoNotTripTheBreaker(t *testing.T) {
	ct := &fakeConntrack{err: conntrack.ErrNotFound}
	s := NewServer(logging.NewLogger(&bytes.Buffer{}), Options{Conntrack: ct})
	for i := 0; i < 20; i++ {
		s.redirected(&net.UDPAddr{IP: net.ParseIP("198.51.100.7"), Port: 1},
			&socket.OriginalDst{IP: net.ParseIP("192.0.2.1"), Port: 8080}, time.Unix(1_800_000_000, 0))
	}
	if ct.calls() != 20 || s.ctPaused.Load() != 0 {
		t.Fatalf("calls %d, paused %d", ct.calls(), s.ctPaused.Load())
	}
}
