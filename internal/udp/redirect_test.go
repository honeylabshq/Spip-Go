package udp

import (
	"bytes"
	"encoding/json"
	"errors"
	"net"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"spip/internal/logging"
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
		&socket.OriginalDst{IP: net.ParseIP("192.0.2.1"), Port: 8080})
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
	if got := s.redirected(&net.UDPAddr{IP: net.ParseIP("198.51.100.7"), Port: 1}, dst); got != dst {
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
