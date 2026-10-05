// Package quictest builds client Initial packets for tests. It seals packets
// with code written independently of the decoder in package quic, so a round
// trip checks both directions, and it gets real ClientHellos from Go's own
// QUIC-mode TLS client rather than hand-written bytes.
package quictest

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/tls"
	"testing"

	"spip/internal/quic"
)

// Hello returns the ClientHello Go's crypto/tls sends as a QUIC client.
func Hello(t testing.TB, sni string, transportParams []byte) []byte {
	t.Helper()
	qc := tls.QUICClient(&tls.QUICConfig{TLSConfig: &tls.Config{
		ServerName: sni, NextProtos: []string{"h3"}, MinVersion: tls.VersionTLS13,
	}})
	qc.SetTransportParameters(transportParams)
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

// Varint encodes a QUIC variable-length integer.
func Varint(v uint64) []byte {
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

// Crypto builds a CRYPTO frame.
func Crypto(off uint64, data []byte) []byte {
	f := []byte{0x06}
	f = append(f, Varint(off)...)
	f = append(f, Varint(uint64(len(data)))...)
	return append(f, data...)
}

// Seal builds a protected client Initial datagram padded to 1200 bytes.
func Seal(t testing.TB, version uint32, dcid, scid []byte, pn uint64, payload []byte) []byte {
	t.Helper()
	k, err := quic.ClientInitialKeys(version, dcid)
	if err != nil {
		t.Fatal(err)
	}
	initialType := byte(0)
	if version == quic.Version2 {
		initialType = 1
	}
	for len(payload) < 1100 {
		payload = append(payload, 0x00)
	}
	pnLen := 4
	hdr := []byte{0xc0 | initialType<<4 | byte(pnLen-1)}
	hdr = append(hdr, byte(version>>24), byte(version>>16), byte(version>>8), byte(version))
	hdr = append(hdr, byte(len(dcid)))
	hdr = append(hdr, dcid...)
	hdr = append(hdr, byte(len(scid)))
	hdr = append(hdr, scid...)
	hdr = append(hdr, 0x00)
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
