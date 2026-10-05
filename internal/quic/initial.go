// Package quic reads a client's QUIC Initial packets without answering them.
// Initial keys derive from a public salt and the client's Destination
// Connection ID (RFC 9001 section 5.2), so a passive receiver can decrypt the
// first flight and recover the TLS ClientHello.
package quic

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
)

const (
	Version1       uint32 = 0x00000001 // RFC 9000
	Version2       uint32 = 0x6b3343cf // RFC 9369
	VersionDraft29 uint32 = 0xff00001d
)

type versionParams struct {
	salt                       []byte
	keyLabel, ivLabel, hpLabel string
	initialType                byte
	retryType                  byte
}

var versions = map[uint32]versionParams{
	Version1: {
		salt:     mustHex("38762cf7f55934b34d179ae6a4c80cadccbb7f0a"),
		keyLabel: "quic key", ivLabel: "quic iv", hpLabel: "quic hp",
		initialType: 0, retryType: 3,
	},
	Version2: {
		salt:     mustHex("0dede3def700a6db819381be6e269dcbf9bd2ed9"),
		keyLabel: "quicv2 key", ivLabel: "quicv2 iv", hpLabel: "quicv2 hp",
		initialType: 1, retryType: 0,
	},
	VersionDraft29: {
		salt:     mustHex("afbfec289993d24c9e9786f19c6111e04390a899"),
		keyLabel: "quic key", ivLabel: "quic iv", hpLabel: "quic hp",
		initialType: 0, retryType: 3,
	},
}

const maxConnIDLen = 20

// Known reports whether Initial packets of version v can be decrypted.
func Known(v uint32) bool {
	_, ok := versions[v]
	return ok
}

// VersionName is the label stored with each record.
func VersionName(v uint32) string {
	switch v {
	case Version1:
		return "1"
	case Version2:
		return "2"
	case VersionDraft29:
		return "draft-29"
	}
	return fmt.Sprintf("0x%08x", v)
}

var (
	ErrNotQUIC            = errors.New("not a QUIC long-header packet")
	ErrUnsupportedVersion = errors.New("unsupported QUIC version")
	ErrNotInitial         = errors.New("not an Initial packet")
)

// Keys are the client Initial packet protection keys for one connection.
type Keys struct {
	Key, IV, HP []byte
}

// ClientInitialKeys derives the client's Initial keys (RFC 9001 5.2, RFC 9369 3.3).
func ClientInitialKeys(version uint32, dcid []byte) (*Keys, error) {
	vp, ok := versions[version]
	if !ok {
		return nil, ErrUnsupportedVersion
	}
	initial, err := hkdf.Extract(sha256.New, dcid, vp.salt)
	if err != nil {
		return nil, err
	}
	client, err := expandLabel(initial, "client in", 32)
	if err != nil {
		return nil, err
	}
	k := &Keys{}
	if k.Key, err = expandLabel(client, vp.keyLabel, 16); err != nil {
		return nil, err
	}
	if k.IV, err = expandLabel(client, vp.ivLabel, 12); err != nil {
		return nil, err
	}
	if k.HP, err = expandLabel(client, vp.hpLabel, 16); err != nil {
		return nil, err
	}
	return k, nil
}

// expandLabel is TLS 1.3 HKDF-Expand-Label with an empty context.
func expandLabel(secret []byte, label string, n int) ([]byte, error) {
	full := "tls13 " + label
	info := make([]byte, 0, 4+len(full))
	info = append(info, byte(n>>8), byte(n), byte(len(full)))
	info = append(info, full...)
	info = append(info, 0)
	return hkdf.Expand(sha256.New, secret, string(info), n)
}

// Packet is one long-header packet. Frames is set only for an Initial that
// decrypted.
type Packet struct {
	Version  uint32
	DCID     []byte
	SCID     []byte
	Type     byte
	TokenLen int
	PN       uint64
	Frames   *Frames
}

// ParseDatagram returns the coalesced long-header packets of a datagram. A
// packet of an unknown version, or one that fails to decrypt, is returned with
// its header and the error that stopped the walk.
func ParseDatagram(b []byte) ([]*Packet, error) {
	var out []*Packet
	for len(b) > 0 && b[0]&0x80 != 0 {
		p, n, err := parseLong(b)
		if p == nil {
			break
		}
		out = append(out, p)
		if err != nil && !errors.Is(err, ErrNotInitial) {
			return out, err
		}
		if n <= 0 {
			break
		}
		b = b[n:]
	}
	if len(out) == 0 {
		return nil, ErrNotQUIC
	}
	return out, nil
}

func parseLong(b []byte) (*Packet, int, error) {
	if len(b) < 7 {
		return nil, 0, ErrNotQUIC
	}
	p := &Packet{Version: binary.BigEndian.Uint32(b[1:5]), Type: (b[0] & 0x30) >> 4}
	off := 5
	dcil := int(b[off])
	off++
	if off+dcil >= len(b) {
		return nil, 0, ErrNotQUIC
	}
	p.DCID = append([]byte(nil), b[off:off+dcil]...)
	off += dcil
	scil := int(b[off])
	off++
	if off+scil > len(b) {
		return nil, 0, ErrNotQUIC
	}
	p.SCID = append([]byte(nil), b[off:off+scil]...)
	off += scil

	vp, known := versions[p.Version]
	if !known {
		return p, 0, ErrUnsupportedVersion
	}
	if dcil > maxConnIDLen || scil > maxConnIDLen {
		return nil, 0, ErrNotQUIC
	}
	if p.Type != vp.initialType {
		return p, skipLength(b, off, p.Type == vp.retryType), ErrNotInitial
	}

	tokenLen, n, err := readVarint(b[off:])
	if err != nil {
		return p, 0, err
	}
	off += n
	if tokenLen > uint64(len(b)-off) {
		return p, 0, errors.New("token length beyond datagram")
	}
	p.TokenLen = int(tokenLen)
	off += int(tokenLen)

	length, n, err := readVarint(b[off:])
	if err != nil {
		return p, 0, err
	}
	off += n
	pnOffset := off
	if length < 20 || length > uint64(len(b)-pnOffset) {
		return p, 0, fmt.Errorf("packet length %d does not fit datagram", length)
	}
	end := pnOffset + int(length)

	keys, err := ClientInitialKeys(p.Version, p.DCID)
	if err != nil {
		return p, 0, err
	}
	plain, pn, err := unprotect(b[:end], pnOffset, keys)
	if err != nil {
		return p, 0, err
	}
	p.PN = pn
	// CRYPTO data read before a disallowed frame is authenticated and kept.
	p.Frames, _ = parseFrames(plain)
	return p, end, nil
}

// skipLength returns the size of a 0-RTT or Handshake packet, or 0 when it
// cannot be determined (Retry carries no length).
func skipLength(b []byte, off int, retry bool) int {
	if retry {
		return 0
	}
	length, n, err := readVarint(b[off:])
	if err != nil || length > uint64(len(b)-off-n) {
		return 0
	}
	return off + n + int(length)
}

func unprotect(pkt []byte, pnOffset int, k *Keys) ([]byte, uint64, error) {
	if pnOffset+4+aes.BlockSize > len(pkt) {
		return nil, 0, errors.New("packet too short for header protection sample")
	}
	hdr := append([]byte(nil), pkt...)
	hp, err := aes.NewCipher(k.HP)
	if err != nil {
		return nil, 0, err
	}
	mask := make([]byte, aes.BlockSize)
	hp.Encrypt(mask, hdr[pnOffset+4:pnOffset+4+aes.BlockSize])
	hdr[0] ^= mask[0] & 0x0f
	pnLen := int(hdr[0]&0x03) + 1
	var pn uint64
	for i := 0; i < pnLen; i++ {
		hdr[pnOffset+i] ^= mask[1+i]
		pn = pn<<8 | uint64(hdr[pnOffset+i])
	}

	block, err := aes.NewCipher(k.Key)
	if err != nil {
		return nil, 0, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, 0, err
	}
	nonce := append([]byte(nil), k.IV...)
	for i := 0; i < 8; i++ {
		nonce[len(nonce)-1-i] ^= byte(pn >> (8 * i))
	}
	payloadStart := pnOffset + pnLen
	plain, err := aead.Open(nil, nonce, hdr[payloadStart:], hdr[:payloadStart])
	if err != nil {
		return nil, 0, fmt.Errorf("initial packet did not decrypt: %w", err)
	}
	return plain, pn, nil
}

// readVarint decodes a QUIC variable-length integer (RFC 9000 section 16).
func readVarint(b []byte) (uint64, int, error) {
	if len(b) == 0 {
		return 0, 0, errors.New("truncated varint")
	}
	n := 1 << (b[0] >> 6)
	if len(b) < n {
		return 0, 0, errors.New("truncated varint")
	}
	v := uint64(b[0] & 0x3f)
	for i := 1; i < n; i++ {
		v = v<<8 | uint64(b[i])
	}
	return v, n, nil
}

func mustHex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}
