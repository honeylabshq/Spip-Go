package udp

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"

	"spip/internal/logging"
	"spip/internal/quic"
	"spip/internal/quic/quictest"
	"spip/pkg/socket"
)

type rig struct {
	t   *testing.T
	out *bytes.Buffer
	s   *Server
	now time.Time
}

func newRig(t *testing.T, opt Options) *rig {
	out := &bytes.Buffer{}
	opt.Name = "spip-test"
	opt.CaptureClientHello = true
	r := &rig{t: t, out: out, now: time.Unix(1_800_000_000, 0)}
	r.s = NewServer(logging.NewLogger(out), opt)
	r.s.now = func() time.Time { return r.now }
	return r
}

func (r *rig) send(payload []byte, srcPort int, dstPort uint16) {
	r.s.HandleDatagram(payload,
		&net.UDPAddr{IP: net.ParseIP("198.51.100.7"), Port: srcPort},
		&socket.OriginalDst{IP: net.ParseIP("192.0.2.1").To4(), Port: dstPort})
}

// records returns the ECS records written so far (log lines excluded).
func (r *rig) records() []map[string]any {
	var out []map[string]any
	for _, line := range strings.Split(strings.TrimSpace(r.out.String()), "\n") {
		if line == "" {
			continue
		}
		var m map[string]any
		if err := json.Unmarshal([]byte(line), &m); err != nil {
			r.t.Fatalf("bad json %q: %v", line, err)
		}
		if _, isLog := m["record_type"]; isLog {
			continue
		}
		out = append(out, m)
	}
	return out
}

func get(m map[string]any, path string) any {
	var cur any = m
	for _, k := range strings.Split(path, ".") {
		mm, ok := cur.(map[string]any)
		if !ok {
			return nil
		}
		cur = mm[k]
	}
	return cur
}

func dnsQuery(t *testing.T) []byte {
	b, _ := hex.DecodeString("abcd01000001000000000000" + "076578616d706c6503636f6d0000ff0001")
	return b
}

func TestDNSQueryRecord(t *testing.T) {
	r := newRig(t, Options{})
	r.send(dnsQuery(t), 40000, 53)
	recs := r.records()
	if len(recs) != 1 {
		t.Fatalf("%d records", len(recs))
	}
	m := recs[0]
	checks := map[string]any{
		"network.transport": "udp",
		"network.protocol":  "dns",
		"destination.port":  float64(53),
		"dns.question.name": "example.com",
		"dns.question.type": "ANY",
		"dns.type":          "query",
		"event.summary":     "DNS query ANY example.com",
		"event.ingested_by": "spip",
	}
	for path, want := range checks {
		if got := get(m, path); got != want {
			t.Errorf("%s = %v, want %v", path, got, want)
		}
	}
	if cid, _ := get(m, "network.community_id").(string); !strings.HasPrefix(cid, "1:") {
		t.Errorf("community id %q", cid)
	}
	if get(m, "tls") != nil || get(m, "quic") != nil {
		t.Error("DNS record carries tls or quic fields")
	}
}

func TestRawUDPRecord(t *testing.T) {
	r := newRig(t, Options{})
	r.send([]byte("\xff\xff\xff\xffgetstatus\n"), 40001, 27960)
	m := r.records()[0]
	if get(m, "network.transport") != "udp" || get(m, "network.protocol") != nil {
		t.Errorf("transport/protocol %v %v", get(m, "network.transport"), get(m, "network.protocol"))
	}
	if get(m, "event.original_payload_hex") != "ffffffff676574737461747573"+"0a" {
		t.Errorf("payload hex %v", get(m, "event.original_payload_hex"))
	}
}

var tp = []byte{0x01, 0x04, 0x80, 0x00, 0x75, 0x30, 0x0f, 0x04, 1, 2, 3, 4}

// A ClientHello split across two datagrams, plus three retransmissions of the
// first, must produce exactly one record with the QUIC JA4.
func TestQUICAttemptIsOneRecord(t *testing.T) {
	r := newRig(t, Options{})
	hello := quictest.Hello(t, "victim.example", tp)
	dcid := []byte{1, 2, 3, 4, 5, 6, 7, 8}
	d1 := quictest.Seal(t, quic.Version1, dcid, []byte{7}, 0, quictest.Crypto(0, hello[:60]))
	d2 := quictest.Seal(t, quic.Version1, dcid, []byte{7}, 1, quictest.Crypto(60, hello[60:]))
	r.send(d1, 50000, 443)
	if n := len(r.records()); n != 0 {
		t.Fatalf("logged %d records before the hello was complete", n)
	}
	r.send(d2, 50000, 443)
	for i := 0; i < 3; i++ {
		r.send(d1, 50000, 443)
	}
	recs := r.records()
	if len(recs) != 1 {
		t.Fatalf("%d records, want 1", len(recs))
	}
	m := recs[0]
	if ja4, _ := get(m, "tls.client.hash.ja4").(string); !strings.HasPrefix(ja4, "q13d") {
		t.Errorf("ja4 %q", ja4)
	}
	checks := map[string]any{
		"network.transport":                       "udp",
		"network.protocol":                        "quic",
		"destination.port":                        float64(443),
		"tls.client.server_name":                  "victim.example",
		"quic.version":                            "1",
		"quic.dcid":                               "0102030405060708",
		"quic.hello_complete":                     true,
		"quic.decrypted":                          true,
		"quic.datagrams":                          float64(2),
		"event.summary":                           "QUIC v1 Initial sni=victim.example alpn=h3",
		"quic.client.transport_parameters.string": "1=30000,f/4",
	}
	for path, want := range checks {
		if got := get(m, path); got != want {
			t.Errorf("%s = %v, want %v", path, got, want)
		}
	}
	if h, _ := get(m, "tls.client.hello_hex").(string); !strings.HasPrefix(h, "160301") {
		t.Errorf("hello_hex not a TLS record: %.12s", h)
	}
	if _, retrans := r.s.asm.Stats(); retrans != 3 {
		t.Errorf("retransmits %d, want 3", retrans)
	}
}

func TestIncompleteQUICIsRecordedOnExpiry(t *testing.T) {
	r := newRig(t, Options{})
	hello := quictest.Hello(t, "x.example", tp)
	d := quictest.Seal(t, quic.Version1, []byte{9, 9, 9, 9, 9, 9, 9, 9}, nil, 0, quictest.Crypto(0, hello[:30]))
	r.send(d, 50001, 8443)
	r.now = r.now.Add(quic.PendingTTL)
	for _, at := range r.s.asm.Expire(r.now) {
		r.s.logAttempt(at)
	}
	recs := r.records()
	if len(recs) != 1 {
		t.Fatalf("%d records", len(recs))
	}
	if get(recs[0], "quic.hello_complete") != false || get(recs[0], "quic.crypto_bytes") != float64(30) {
		t.Errorf("incomplete record %v", recs[0]["quic"])
	}
	if get(recs[0], "tls") != nil {
		t.Error("incomplete attempt claims TLS fields")
	}
}

func TestVersionProbeAndNoise(t *testing.T) {
	r := newRig(t, Options{})
	probe := append([]byte{0xc0, 0x0a, 0x0a, 0x0a, 0x0a, 8, 1, 2, 3, 4, 5, 6, 7, 8, 0}, make([]byte, 1200)...)
	r.send(probe, 50002, 443)
	// High bit set but short and without the fixed bit: not QUIC.
	r.send([]byte{0x80, 0x00, 0x00, 0x00, 0x05, 0x01, 0xaa, 0x00, 0x11, 0x22}, 50003, 5683)
	recs := r.records()
	if len(recs) != 2 {
		t.Fatalf("%d records", len(recs))
	}
	if get(recs[0], "quic.version") != "0x0a0a0a0a" || get(recs[0], "network.protocol") != "quic" {
		t.Errorf("probe %v", recs[0]["quic"])
	}
	if get(recs[1], "network.protocol") != nil {
		t.Errorf("noise labelled %v", get(recs[1], "network.protocol"))
	}
}

func TestIgnoredSourceLeavesNoRecord(t *testing.T) {
	r := newRig(t, Options{IgnoreNets: []netip.Prefix{netip.MustParsePrefix("198.51.100.0/24")}})
	r.send(dnsQuery(t), 40000, 53)
	if len(r.records()) != 0 || r.s.dropped.Load() != 1 {
		t.Fatal("ignored source was recorded")
	}
}

func TestGlobalRateLimit(t *testing.T) {
	r := newRig(t, Options{RatePerSecond: 1, Burst: 3, SourceRate: 100, SourceBurst: 100})
	for i := 0; i < 10; i++ {
		r.send(dnsQuery(t), 40000+i, 53)
	}
	if n := len(r.records()); n != 3 || r.s.limited.Load() != 7 {
		t.Fatalf("records %d limited %d", n, r.s.limited.Load())
	}
}

// One source cannot spend the whole budget; others still get through.
func TestPerSourceRateLimit(t *testing.T) {
	r := newRig(t, Options{SourceRate: 1, SourceBurst: 2})
	for i := 0; i < 10; i++ {
		r.send(dnsQuery(t), 40000+i, 53)
	}
	r.s.HandleDatagram(dnsQuery(t), &net.UDPAddr{IP: net.ParseIP("203.0.113.9"), Port: 1}, &socket.OriginalDst{IP: net.IPv4(192, 0, 2, 1), Port: 53})
	if n := len(r.records()); n != 3 || r.s.sourceLimit.Load() != 8 {
		t.Fatalf("records %d source-limited %d", n, r.s.sourceLimit.Load())
	}
}

func TestSourceLimiterBounded(t *testing.T) {
	l := newSourceLimiter(1, 1, 4)
	now := time.Unix(0, 0)
	for i := 0; i < 4; i++ {
		if !l.allow(netip.AddrFrom4([4]byte{10, 0, 0, byte(i)}), now) {
			t.Fatal("refused under capacity")
		}
	}
	if l.allow(netip.MustParseAddr("10.0.0.99"), now) {
		t.Fatal("admitted a new source with the table full and nothing idle")
	}
	if !l.allow(netip.MustParseAddr("10.0.0.99"), now.Add(2*time.Minute)) {
		t.Fatal("idle entries were not evicted")
	}
	if sourceKey(netip.MustParseAddr("2001:db8::1")) != sourceKey(netip.MustParseAddr("2001:db8::ffff")) {
		t.Fatal("IPv6 sources in one /64 must share a bucket")
	}
}

func TestStoredPayloadIsCapped(t *testing.T) {
	r := newRig(t, Options{})
	r.send(make([]byte, 9000), 40000, 9999)
	m := r.records()[0]
	if h, _ := get(m, "event.original_payload_hex").(string); len(h) != 2*MaxStoredPayload {
		t.Errorf("stored %d hex chars", len(h))
	}
	if get(m, "source.bytes") != float64(9000) {
		t.Errorf("source.bytes %v, want the full datagram size", get(m, "source.bytes"))
	}
}

// NetBIOS shares the DNS wire format; it is recorded as netbios and its names
// stay out of the DNS question fields.
func TestNetBIOSIsNotRecordedAsDNS(t *testing.T) {
	r := newRig(t, Options{})
	b, _ := hex.DecodeString("35370100000100000000000020434b4141414141414141414141414141414141414141414141414141414141410000210001")
	r.send(b, 40000, 137)
	m := r.records()[0]
	if get(m, "network.protocol") != "netbios" || m["dns"] != nil {
		t.Fatalf("protocol %v, dns %v", get(m, "network.protocol"), m["dns"])
	}
	if get(m, "event.summary") != "NetBIOS node status query *" {
		t.Errorf("summary %v", get(m, "event.summary"))
	}
}
