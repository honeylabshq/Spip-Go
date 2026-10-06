package dnsinfo

import (
	"encoding/hex"
	"strings"
	"testing"
)

func h(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(strings.Join(strings.Fields(s), ""))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// dig example.com A with its default EDNS: UDP size 1232, a cookie option.
func TestQueryWithEDNS(t *testing.T) {
	b := h(t, `
		abcd 0120 0001 0000 0000 0001
		07 6578616d706c65 03 636f6d 00 0001 0001
		00 0029 04d0 00000000 000c 000a 0008 0102030405060708`)
	i, err := Parse(b)
	if err != nil {
		t.Fatal(err)
	}
	if i.ID != 0xabcd || i.Response || i.OpCode != "QUERY" {
		t.Errorf("header %+v", i)
	}
	if len(i.Questions) != 1 || i.Questions[0] != (Question{"example.com", "A", "IN"}) {
		t.Errorf("questions %+v", i.Questions)
	}
	if !i.EDNS || i.EDNSUDPSize != 1232 || i.EDNSDO || len(i.EDNSOptions) != 1 || i.EDNSOptions[0] != 10 {
		t.Errorf("edns %+v", i)
	}
	if got := strings.Join(i.Flags, ","); got != "RD,AD" {
		t.Errorf("flags %q", got)
	}
	if i.Summary() != "DNS query A example.com" {
		t.Errorf("summary %q", i.Summary())
	}
}

// The classic fingerprinting probe: TXT in the CHAOS class for version.bind.
func TestVersionBindProbe(t *testing.T) {
	b := h(t, `0001 0000 0001 0000 0000 0000
		07 76657273696f6e 04 62696e64 00 0010 0003`)
	i, err := Parse(b)
	if err != nil {
		t.Fatal(err)
	}
	if i.Questions[0] != (Question{"version.bind", "TXT", "CH"}) {
		t.Errorf("question %+v", i.Questions[0])
	}
	if i.Summary() != "DNS query TXT/CH version.bind" {
		t.Errorf("summary %q", i.Summary())
	}
}

// ANY with DNSSEC OK and a 4096-byte buffer is the amplification shape.
func TestAmplificationQuery(t *testing.T) {
	b := h(t, `1234 0100 0001 0000 0000 0001
		03 697363 03 6f7267 00 00ff 0001
		00 0029 1000 00008000 0000`)
	i, err := Parse(b)
	if err != nil {
		t.Fatal(err)
	}
	if i.Questions[0].Type != "ANY" || !i.EDNSDO || i.EDNSUDPSize != 4096 {
		t.Errorf("%+v", i)
	}
}

// A response nobody asked for is backscatter: the sensor's address was spoofed
// as the source of someone else's query.
func TestUnsolicitedResponse(t *testing.T) {
	b := h(t, `beef 8180 0001 0001 0000 0000
		07 6578616d706c65 03 636f6d 00 0001 0001
		c00c 0001 0001 0000012c 0004 5db8d822`)
	i, err := Parse(b)
	if err != nil {
		t.Fatal(err)
	}
	if !i.Response || i.Answers != 1 || i.RCode != "NOERROR" {
		t.Errorf("%+v", i)
	}
	if i.Summary() != "DNS response A example.com" {
		t.Errorf("summary %q", i.Summary())
	}
}

func TestRejectsNonDNS(t *testing.T) {
	for _, b := range [][]byte{
		[]byte("hello\n"),
		h(t, "0102030405060708090a0b0c0d0e0f10"), // header-sized junk, question count 0x0506
		h(t, "abcd 0100 0000 0000 0000 0000"),    // a query with no question
		{},
	} {
		if _, err := Parse(b); err == nil {
			t.Errorf("%x parsed as DNS", b)
		}
	}
}

func TestUnknownTypeNames(t *testing.T) {
	b := h(t, `0001 0000 0001 0000 0000 0000
		03 777777 07 6578616d706c65 03 636f6d 00 0041 0001`)
	i, err := Parse(b)
	if err != nil {
		t.Fatal(err)
	}
	if i.Questions[0].Type != "HTTPS" {
		t.Errorf("type %q", i.Questions[0].Type)
	}
}

// Labels may carry any byte. They must reach records escaped, not raw.
func TestNameIsSanitised(t *testing.T) {
	b := h(t, `0001 0000 0001 0000 0000 0000
		05 3c623e0a00 03 636f6d 00 0001 0001`)
	i, err := Parse(b)
	if err != nil {
		t.Fatal(err)
	}
	if got := i.Questions[0].Name; got != `<b>\x0a\x00.com` {
		t.Errorf("name %q", got)
	}
}

// Real datagrams captured on 2026-10-05 and 06 whose first twelve bytes read as
// a DNS header. Each was recorded as DNS before framing was checked.
func TestOtherProtocolsAreNotDNS(t *testing.T) {
	for _, c := range []struct{ name, hex string }{
		{"Sun RPC portmap call", "1aa9ffe10000000000000002000186a0000000020000000400000000000000000000000000000000"},
		{"NTP client request", "e30004fa000100000001000000000000000000000000000000000000000000000000000000000000c54f234b71b152f3"},
		{"DTLS ClientHello", "16feff000000000000000000660100005a000000000000005afefd29352bf9c774a89a12bf07b27bfdd2b977631f9e9b889418188a1b646061e43800000032c02ccca9c0adc00ac02bc0acc009c030cca8c014c02fc013009dc09d0035009cc09c002f009fccaac09f0039009ec09e00330100"},
		{"RIP request", "01010000000200004400000000000000000000000000000f"},
		{"IPMI RMCP ping", "0600ff07000000000000000000092018c88100388e04b5"},
		{"RPC to port 1629", "1a09faba000000000000000255555555000000010000000100000000000000000000000000000000ffff55120000003c00000001000000020000000000000000"},
	} {
		if i, err := Parse(h(t, c.hex)); err == nil {
			t.Errorf("%s parsed as DNS: %q", c.name, i.Summary())
		}
	}
}

func TestRealQueriesStillParse(t *testing.T) {
	for _, c := range []struct{ hex, summary string }{
		{"1271010000010000000000010477697363036564750000ff00010000292000000080000000", "DNS query ANY wisc.edu"},
		{"000000000001000000000000095f7365727669636573075f646e732d7364045f756470056c6f63616c00000c0001", "DNS query PTR _services._dns-sd._udp.local"},
	} {
		i, err := Parse(h(t, c.hex))
		if err != nil {
			t.Fatalf("%s: %v", c.summary, err)
		}
		if i.Summary() != c.summary {
			t.Errorf("summary %q, want %q", i.Summary(), c.summary)
		}
	}
}

// The node status probe scanners send to 137/udp: the wildcard name "*",
// type NBSTAT (0x21, which DNS would read as SRV).
func TestNetBIOSNodeStatus(t *testing.T) {
	i, err := Parse(h(t, "35370100000100000000000020434b4141414141414141414141414141414141414141414141414141414141410000210001"))
	if err != nil {
		t.Fatal(err)
	}
	if i.NetBIOS == nil || i.NetBIOS.Name != "*" || i.NetBIOS.Type != "NBSTAT" {
		t.Fatalf("netbios %+v", i.NetBIOS)
	}
	if i.Summary() != "NetBIOS node status query *" {
		t.Errorf("summary %q", i.Summary())
	}
}

func TestQuestionTypeAndClassMustBeValid(t *testing.T) {
	for _, s := range []string{
		"0001 0100 0001 0000 0000 0000 07 6578616d706c65 03 636f6d 00 0000 0001",            // type 0
		"0001 0100 0001 0000 0000 0000 07 6578616d706c65 03 636f6d 00 0001 0000",            // class 0
		"0001 0100 0001 0000 0000 0000 07 6578616d706c65 03 636f6d 00 0001 0001 ff",         // trailing data
		"0001 0100 0001 0000 0000 0000 07 6578616d706c65 03 636f6d 00 0001 0001 0000000000", // five padding bytes
		"0001 1800 0001 0000 0000 0000 07 6578616d706c65 03 636f6d 00 0001 0001",            // opcode 3
		"0001 8180 0000 0001 0000 0000 c00c 0001 0001 0000012c 0004 5db8d822",               // answer, no question
	} {
		if _, err := Parse(h(t, s)); err == nil {
			t.Errorf("%s parsed as DNS", s)
		}
	}
	// mDNS sets the top class bit to ask for a unicast answer.
	if _, err := Parse(h(t, "0000 0000 0001 0000 0000 0000 05 5f68747470 04 5f746370 05 6c6f63616c 00 000c 8001")); err != nil {
		t.Errorf("mDNS unicast-response question rejected: %v", err)
	}
}

// Seen on 53/udp: version.bind probes with a newline or a zero byte appended.
func TestProbePaddingIsToleratedAndCounted(t *testing.T) {
	for _, tail := range []string{"0a", "00", "0d0a"} {
		i, err := Parse(h(t, "34ef 0100 0001 0000 0000 0000 07 76657273696f6e 04 62696e64 00 0010 0003"+tail))
		if err != nil {
			t.Fatalf("tail %s: %v", tail, err)
		}
		if i.Trailing != len(tail)/2 || i.Summary() != "DNS query TXT/CH version.bind" {
			t.Errorf("tail %s: trailing %d, summary %q", tail, i.Trailing, i.Summary())
		}
	}
}
