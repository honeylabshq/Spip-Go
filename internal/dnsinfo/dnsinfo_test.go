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
