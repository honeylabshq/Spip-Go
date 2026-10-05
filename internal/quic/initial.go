// Package quic reads the client's first flight of a QUIC connection without
// answering it.
//
// QUIC encrypts even its first packet, but the Initial packet keys are derived
// from a public salt and the Destination Connection ID the client chose, so any
// observer can recompute them (RFC 9001 section 5.2). That is deliberate in the
// protocol: Initial protection guards against off-path tampering, not against
// reading. A client sends its whole TLS ClientHello in CRYPTO frames inside its
// Initial packets before the server says anything, so a capture-only sensor
// sees the same handshake a full server would.
package quic

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
)

// Versions this package can decrypt. Anything else still has its invariant
// header parsed (RFC 8999) so a version-negotiation probe is recorded with the
// version it tried.
const (
	Version1       uint32 = 0x00000001 // RFC 9000
	Version2       uint32 = 0x6b3343cf // RFC 9369
	VersionDraft29 uint32 = 0xff00001d
)

type versionParams struct {
	salt                       []byte
	keyLabel, ivLabel, hpLabel string
	initialType                byte // long-header type bits for Initial
}

var versions = map[uint32]versionParams{
	Version1: {
		salt:     mustHex("38762cf7f55934b34d179ae6a4c80cadccbb7f0a"),
		keyLabel: "quic key", ivLabel: "quic iv", hpLabel: "quic hp",
		initialType: 0,
	},
	Version2: {
		salt:     mustHex("0dede3def700a6db819381be6e269dcbf9bd2ed9"),
		keyLabel: "quicv2 key", ivLabel: "quicv2 iv", hpLabel: "quicv2 hp",
		initialType: 1,
	},
	VersionDraft29: {
		salt:     mustHex("afbfec289993d24c9e9786f19c6111e04390a899"),
		keyLabel: "quic key", ivLabel: "quic iv", hpLabel: "quic hp",
		initialType: 0,
	},
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
	case 0:
		return "negotiation"
	}
	return fmt.Sprintf("0x%08x", v)
}

var (
	// ErrNotQUIC means the datagram does not start with a long header.
	ErrNotQUIC = errors.New("not a QUIC long-header packet")
	// ErrUnsupportedVersion means the header parsed but this package has no
	// keys for the version. The returned Packet still carries the header.
	ErrUnsupportedVersion = errors.New("unsupported QUIC version")
	// ErrNotInitial means a known version but a packet type other than Initial
	// (0-RTT, Handshake or Retry), which a capture-only sensor cannot decrypt.
	ErrNotInitial = errors.New("not an Initial packet")
)

// Keys are the client Initial packet protection keys for one connection.
type Keys struct {
	Key, IV, HP []byte
}

// ClientInitialKeys derives the client's Initial keys from the Destination
// Connection ID of its first packet (RFC 9001 section 5.2, RFC 9369 3.3).
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
	info = append(info, 0) // empty context
	return hkdf.Expand(sha256.New, secret, string(info), n)
}

// Packet is one long-header packet from a datagram. Header fields are always
// set when err is nil or ErrUnsupportedVersion/ErrNotInitial; Frames only when
// the packet was an Initial that decrypted.
type Packet struct {
	Version  uint32
	DCID     []byte
	SCID     []byte
	Type     byte // raw long-header type bits
	TokenLen int
	PN       uint64
	Frames   *Frames
}

// ParseDatagram walks every coalesced long-header packet in a datagram and
// returns them in order. A client's first datagram is normally one Initial
// padded to 1200 bytes, but Initial plus 0-RTT coalescing is legal. The first
// error that stops parsing is returned alongside whatever was parsed before it;
// unsupported versions and non-Initial packets are reported per packet rather
// than stopping the walk.
func ParseDatagram(b []byte) ([]*Packet, error) {
	var out []*Packet
	for len(b) > 0 {
		if b[0]&0x80 == 0 {
			if len(out) == 0 {
				return nil, ErrNotQUIC
			}
			break // a short-header packet or padding after the long ones
		}
		p, n, err := parseLong(b)
		if p != nil {
			out = append(out, p)
		}
		if err != nil && !errors.Is(err, ErrUnsupportedVersion) && !errors.Is(err, ErrNotInitial) {
			return out, err
		}
		if n <= 0 || errors.Is(err, ErrUnsupportedVersion) {
			break // without keys the packet length field cannot be trusted
		}
		b = b[n:]
	}
	if len(out) == 0 {
		return nil, ErrNotQUIC
	}
	return out, nil
}

// parseLong parses one long-header packet at the start of b and returns it with
// the number of bytes it occupied.
func parseLong(b []byte) (*Packet, int, error) {
	if len(b) < 7 {
		return nil, 0, ErrNotQUIC
	}
	p := &Packet{Version: binary.BigEndian.Uint32(b[1:5])}
	off := 5
	dcil := int(b[off])
	off++
	if dcil > 255 || off+dcil > len(b) {
		return nil, 0, ErrNotQUIC
	}
	p.DCID = append([]byte(nil), b[off:off+dcil]...)
	off += dcil
	if off >= len(b) {
		return nil, 0, ErrNotQUIC
	}
	scil := int(b[off])
	off++
	if off+scil > len(b) {
		return nil, 0, ErrNotQUIC
	}
	p.SCID = append([]byte(nil), b[off:off+scil]...)
	off += scil
	p.Type = (b[0] & 0x30) >> 4

	vp, known := versions[p.Version]
	if !known {
		return p, 0, ErrUnsupportedVersion
	}
	if dcil > 20 || scil > 20 {
		return nil, 0, fmt.Errorf("connection id longer than 20 bytes")
	}

	if p.Type != vp.initialType {
		// Skip it if the length can be read: types other than Retry carry one.
		return p, skipNonInitial(b, off, p, vp), ErrNotInitial
	}

	// From here on the header is known, so failures return it with the error:
	// the caller can still record a QUIC attempt that did not decrypt.
	tokenLen, n, err := readVarint(b[off:])
	if err != nil {
		return p, 0, err
	}
	off += n
	if tokenLen > uint64(len(b)-off) {
		return p, 0, fmt.Errorf("token length beyond datagram")
	}
	p.TokenLen = int(tokenLen)
	off += int(tokenLen)

	length, n, err := readVarint(b[off:])
	if err != nil {
		return p, 0, err
	}
	off += n
	pnOffset := off
	if length > uint64(len(b)-pnOffset) || length < 20 {
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
	// A frame the spec does not allow in an Initial ends the parse, but the
	// CRYPTO data read before it is real and authenticated, so it is kept.
	fr, _ := parseFrames(plain)
	p.Frames = fr
	return p, end, nil
}

// skipNonInitial returns the size of a 0-RTT or Handshake packet so the walk
// can continue past it, or 0 when it cannot tell.
func skipNonInitial(b []byte, off int, p *Packet, vp versionParams) int {
	retry := byte(3)
	if p.Version == Version2 {
		retry = 0
	}
	if p.Type == retry {
		return 0
	}
	length, n, err := readVarint(b[off:])
	if err != nil {
		return 0
	}
	end := off + n + int(length)
	if length > uint64(len(b)) || end > len(b) {
		return 0
	}
	return end
}

// unprotect removes header protection and decrypts the payload of the packet
// pkt, whose packet number starts at pnOffset. It works on a copy.
func unprotect(pkt []byte, pnOffset int, k *Keys) ([]byte, uint64, error) {
	if pnOffset+4+16 > len(pkt) {
		return nil, 0, fmt.Errorf("packet too short for header protection sample")
	}
	hdr := append([]byte(nil), pkt...)
	block, err := aes.NewCipher(k.HP)
	if err != nil {
		return nil, 0, err
	}
	mask := make([]byte, 16)
	block.Encrypt(mask, hdr[pnOffset+4:pnOffset+4+16])
	hdr[0] ^= mask[0] & 0x0f // long header: low four bits are protected
	pnLen := int(hdr[0]&0x03) + 1
	var pn uint64
	for i := 0; i < pnLen; i++ {
		hdr[pnOffset+i] ^= mask[1+i]
		pn = pn<<8 | uint64(hdr[pnOffset+i])
	}

	aesKey, err := aes.NewCipher(k.Key)
	if err != nil {
		return nil, 0, err
	}
	aead, err := cipher.NewGCM(aesKey)
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
		return 0, 0, fmt.Errorf("truncated varint")
	}
	n := 1 << (b[0] >> 6)
	if len(b) < n {
		return 0, 0, fmt.Errorf("truncated varint")
	}
	v := uint64(b[0] & 0x3f)
	for i := 1; i < n; i++ {
		v = v<<8 | uint64(b[i])
	}
	return v, n, nil
}

func mustHex(s string) []byte {
	out := make([]byte, len(s)/2)
	for i := range out {
		out[i] = unhex(s[2*i])<<4 | unhex(s[2*i+1])
	}
	return out
}

func unhex(c byte) byte {
	switch {
	case c >= '0' && c <= '9':
		return c - '0'
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10
	}
	panic("bad hex in constant")
}
