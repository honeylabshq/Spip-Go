package quic

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"strings"
	"testing"
	"time"
)

func unhexT(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(strings.ReplaceAll(s, " ", ""))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// RFC 9001 appendix A.1: keys for DCID 0x8394c8f03e515708.
func TestClientInitialKeysRFC9001(t *testing.T) {
	k, err := ClientInitialKeys(Version1, unhexT(t, "8394c8f03e515708"))
	if err != nil {
		t.Fatal(err)
	}
	want := map[string][2][]byte{
		"key": {k.Key, unhexT(t, "1f369613dd76d5467730efcbe3b1a22d")},
		"iv":  {k.IV, unhexT(t, "fa044b2f42a3fd3b46fb255c")},
		"hp":  {k.HP, unhexT(t, "9f50449e04a0e810283a1e9933adedd2")},
	}
	for name, kv := range want {
		if !bytes.Equal(kv[0], kv[1]) {
			t.Errorf("%s = %x, want %x", name, kv[0], kv[1])
		}
	}
}

// RFC 9369 appendix A.1: the same DCID under QUIC version 2.
func TestClientInitialKeysRFC9369(t *testing.T) {
	k, err := ClientInitialKeys(Version2, unhexT(t, "8394c8f03e515708"))
	if err != nil {
		t.Fatal(err)
	}
	want := map[string][2][]byte{
		"key": {k.Key, unhexT(t, "8b1a0bc121284290a29e0971b5cd045d")},
		"iv":  {k.IV, unhexT(t, "91f73e2351d8fa91660e909f")},
		"hp":  {k.HP, unhexT(t, "45b95e15235d6f45a6b19cbcb0294ba9")},
	}
	for name, kv := range want {
		if !bytes.Equal(kv[0], kv[1]) {
			t.Errorf("%s = %x, want %x", name, kv[0], kv[1])
		}
	}
}

// realHello asks Go's own QUIC-mode TLS client for its first flight, which is
// exactly the ClientHello a QUIC client puts into CRYPTO frames.
func realHello(t *testing.T, sni string, tp []byte) []byte {
	t.Helper()
	qc := tls.QUICClient(&tls.QUICConfig{TLSConfig: &tls.Config{
		ServerName: sni, NextProtos: []string{"h3"}, MinVersion: tls.VersionTLS13,
	}})
	qc.SetTransportParameters(tp)
	if err := qc.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	defer qc.Close()
	var hello []byte
	for {
		ev := qc.NextEvent()
		if ev.Kind == tls.QUICNoEvent {
			break
		}
		if ev.Kind == tls.QUICWriteData && ev.Level == tls.QUICEncryptionLevelInitial {
			hello = append(hello, ev.Data...)
		}
	}
	if len(hello) == 0 || hello[0] != 0x01 {
		t.Fatalf("no ClientHello from crypto/tls")
	}
	return hello
}

func varint(v uint64) []byte {
	switch {
	case v < 1<<6:
		return []byte{byte(v)}
	case v < 1<<14:
		return []byte{0x40 | byte(v>>8), byte(v)}
	case v < 1<<30:
		return []byte{0x80 | byte(v>>24), byte(v >> 16), byte(v >> 8), byte(v)}
	}
	return []byte{0xc0 | byte(v>>56), byte(v >> 48), byte(v >> 40), byte(v >> 32), byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v)}
}

func cryptoFrame(off uint64, data []byte) []byte {
	f := []byte{0x06}
	f = append(f, varint(off)...)
	f = append(f, varint(uint64(len(data)))...)
	return append(f, data...)
}

// sealInitial builds a protected client Initial the way a sender does: it is
// written independently of unprotect() so the round trip checks both.
func sealInitial(t *testing.T, version uint32, dcid, scid []byte, pn uint64, payload []byte) []byte {
	t.Helper()
	vp := versions[version]
	k, err := ClientInitialKeys(version, dcid)
	if err != nil {
		t.Fatal(err)
	}
	// Pad the plaintext so the datagram reaches 1200 bytes, as RFC 9000 14.1
	// requires of a client's Initial datagram.
	for len(payload) < 1100 {
		payload = append(payload, 0x00)
	}
	pnLen := 4
	hdr := []byte{0xc0 | vp.initialType<<4 | byte(pnLen-1)}
	hdr = append(hdr, byte(version>>24), byte(version>>16), byte(version>>8), byte(version))
	hdr = append(hdr, byte(len(dcid)))
	hdr = append(hdr, dcid...)
	hdr = append(hdr, byte(len(scid)))
	hdr = append(hdr, scid...)
	hdr = append(hdr, 0x00) // token length
	length := pnLen + len(payload) + 16
	hdr = append(hdr, 0x40|byte(length>>8), byte(length))
	pnOffset := len(hdr)
	hdr = append(hdr, byte(pn>>24), byte(pn>>16), byte(pn>>8), byte(pn))

	blk, _ := aes.NewCipher(k.Key)
	aead, _ := cipher.NewGCM(blk)
	nonce := append([]byte(nil), k.IV...)
	for i := 0; i < 8; i++ {
		nonce[11-i] ^= byte(pn >> (8 * i))
	}
	pkt := aead.Seal(append([]byte(nil), hdr...), nonce, payload, hdr)

	hpb, _ := aes.NewCipher(k.HP)
	mask := make([]byte, 16)
	hpb.Encrypt(mask, pkt[pnOffset+4:pnOffset+20])
	pkt[0] ^= mask[0] & 0x0f
	for i := 0; i < pnLen; i++ {
		pkt[pnOffset+i] ^= mask[1+i]
	}
	return pkt
}

var testTP = []byte{
	0x01, 0x04, 0x80, 0x00, 0x75, 0x30, // max_idle_timeout 30000
	0x04, 0x04, 0x80, 0xf0, 0x00, 0x00, // initial_max_data 15728640
	0x0f, 0x04, 1, 2, 3, 4, // initial_source_connection_id
	0x1b, 0x02, 0xaa, 0xbb, // GREASE id 27
}

func TestSingleDatagramHello(t *testing.T) {
	hello := realHello(t, "example.com", testTP)
	dcid := unhexT(t, "0102030405060708")
	dgram := sealInitial(t, Version1, dcid, []byte{9, 9}, 0, cryptoFrame(0, hello))
	if len(dgram) < 1200 {
		t.Fatalf("datagram %d bytes", len(dgram))
	}
	pkts, err := ParseDatagram(dgram)
	if err != nil {
		t.Fatal(err)
	}
	if len(pkts) != 1 || !bytes.Equal(pkts[0].DCID, dcid) || pkts[0].Version != Version1 {
		t.Fatalf("unexpected packets %+v", pkts)
	}
	a := NewAssembler()
	at := a.Add("k", time.Now(), pkts[0], dgram, nil, true)
	if at == nil || !at.Complete || !bytes.Equal(at.Hello, hello) {
		t.Fatalf("hello not reassembled")
	}
	h, err := ParseHello(at.Hello)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(h.JA4, "q13d") {
		t.Errorf("JA4 %q should start q13d (QUIC, TLS 1.3, SNI present)", h.JA4)
	}
	if h.ServerName != "example.com" || len(h.ALPN) != 1 || h.ALPN[0] != "h3" {
		t.Errorf("sni %q alpn %v", h.ServerName, h.ALPN)
	}
	if h.TransportParamsStr != "1=30000,4=15728640,f/4,grease" {
		t.Errorf("transport params %q", h.TransportParamsStr)
	}
	if len(h.TransportParamsHash) != 12 {
		t.Errorf("hash %q", h.TransportParamsHash)
	}
	if h.HelloRecord[0] != 0x16 || !bytes.Equal(h.HelloRecord[5:], hello) {
		t.Errorf("hello record not wrapped as a TLS handshake record")
	}
}

// A post-quantum ClientHello does not fit one datagram, and Chromium sends its
// CRYPTO frames out of order with PING and PADDING between them. The second
// datagram can even arrive first.
func TestSplitOutOfOrderHello(t *testing.T) {
	hello := realHello(t, "split.example", testTP)
	dcid := unhexT(t, "aabbccddeeff0011")
	a, b, c := hello[:40], hello[40:90], hello[90:]
	p1 := append(cryptoFrame(40, b), 0x01, 0x00, 0x00)
	p1 = append(p1, cryptoFrame(0, a)...)
	p2 := append([]byte{0x01}, cryptoFrame(90, c)...)
	d1 := sealInitial(t, Version1, dcid, nil, 0, p1)
	d2 := sealInitial(t, Version1, dcid, nil, 1, p2)

	as := NewAssembler()
	now := time.Now()
	for i, d := range [][]byte{d2, d1} {
		pkts, err := ParseDatagram(d)
		if err != nil {
			t.Fatal(err)
		}
		at := as.Add("src|dcid", now, pkts[0], d, nil, true)
		if i == 0 && at != nil {
			t.Fatal("completed with a gap")
		}
		if i == 1 {
			if at == nil || !bytes.Equal(at.Hello, hello) {
				t.Fatal("split hello not reassembled")
			}
			if at.Datagrams != 2 || at.Pings != 2 {
				t.Errorf("datagrams %d pings %d", at.Datagrams, at.Pings)
			}
		}
	}
	// The client retransmits because nothing answered: absorbed, not re-logged.
	pkts, _ := ParseDatagram(d1)
	if as.Add("src|dcid", now, pkts[0], d1, nil, true) != nil || as.Retransmits != 1 {
		t.Fatal("retransmission was not absorbed")
	}
}

func TestVersion2Hello(t *testing.T) {
	hello := realHello(t, "v2.example", testTP)
	d := sealInitial(t, Version2, unhexT(t, "1122334455667788"), nil, 0, cryptoFrame(0, hello))
	pkts, err := ParseDatagram(d)
	if err != nil {
		t.Fatal(err)
	}
	if pkts[0].Version != Version2 || pkts[0].Frames == nil || len(pkts[0].Frames.Crypto) != 1 {
		t.Fatalf("v2 packet not decoded: %+v", pkts[0])
	}
}

func TestTamperedPacketIsRejected(t *testing.T) {
	hello := realHello(t, "example.com", testTP)
	d := sealInitial(t, Version1, unhexT(t, "0102030405060708"), nil, 0, cryptoFrame(0, hello))
	d[len(d)-30] ^= 0x01
	if _, err := ParseDatagram(d); err == nil {
		t.Fatal("tampered packet decrypted")
	}
}

// Scanners send unknown versions to make a server list the ones it supports.
// The header is still read so the record names the version that was probed.
func TestVersionNegotiationProbe(t *testing.T) {
	d := []byte{0xc0, 0x1a, 0x2a, 0x3a, 0x4a, 8, 1, 2, 3, 4, 5, 6, 7, 8, 0}
	d = append(d, make([]byte, 1200)...)
	pkts, err := ParseDatagram(d)
	if err != nil {
		t.Fatalf("probe rejected: %v", err)
	}
	if pkts[0].Version != 0x1a2a3a4a || pkts[0].Frames != nil || len(pkts[0].DCID) != 8 {
		t.Fatalf("unexpected %+v", pkts[0])
	}
	if VersionName(pkts[0].Version) != "0x1a2a3a4a" {
		t.Errorf("version name %q", VersionName(pkts[0].Version))
	}
}

func TestNotQUIC(t *testing.T) {
	for _, d := range [][]byte{
		{0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0}, // a DNS header
		[]byte("hello\n"),
		{},
	} {
		if _, err := ParseDatagram(d); !errors.Is(err, ErrNotQUIC) {
			t.Errorf("%x: err %v, want ErrNotQUIC", d, err)
		}
	}
}

func TestIncompleteAttemptExpires(t *testing.T) {
	hello := realHello(t, "example.com", testTP)
	d := sealInitial(t, Version1, unhexT(t, "0102030405060708"), nil, 0, cryptoFrame(0, hello[:50]))
	pkts, _ := ParseDatagram(d)
	as := NewAssembler()
	t0 := time.Now()
	if as.Add("k", t0, pkts[0], d, "meta", true) != nil {
		t.Fatal("partial hello completed")
	}
	if got := as.Expire(t0.Add(time.Second)); len(got) != 0 {
		t.Fatal("expired too early")
	}
	got := as.Expire(t0.Add(PendingTTL))
	if len(got) != 1 || got[0].Complete || got[0].CryptoBytes != 50 || got[0].Meta != "meta" {
		t.Fatalf("expected one incomplete attempt with 50 bytes, got %+v", got)
	}
}

func TestPendingIsBounded(t *testing.T) {
	hello := realHello(t, "example.com", testTP)
	d := sealInitial(t, Version1, unhexT(t, "0102030405060708"), nil, 0, cryptoFrame(0, hello[:20]))
	pkts, _ := ParseDatagram(d)
	as := NewAssembler()
	for i := 0; i < MaxPending+10; i++ {
		as.Add(string(rune(i))+"k", time.Now(), pkts[0], d, nil, true)
	}
	if as.Pending() != MaxPending || as.Overflow != 10 {
		t.Fatalf("pending %d overflow %d", as.Pending(), as.Overflow)
	}
}

// Chromium's version_information carries a random GREASE version at a random
// position. Two connections from one build must hash the same.
func TestVersionInfoGreaseIsNormalised(t *testing.T) {
	a := describeParams([]TransportParam{{ID: 0x11, Value: unhexT(t, "00000001 ea9a7a8a 00000001")}})
	b := describeParams([]TransportParam{{ID: 0x11, Value: unhexT(t, "00000001 00000001 8ada9aaa")}})
	if a != b || a != "11=1;1;grease" {
		t.Fatalf("got %q and %q, want both 11=1;1;grease", a, b)
	}
	if got := describeParams([]TransportParam{{ID: 0x11, Value: unhexT(t, "6b3343cf 6b3343cf 00000001")}}); got != "11=2;2;1" {
		t.Errorf("v2 preference rendered %q", got)
	}
}
