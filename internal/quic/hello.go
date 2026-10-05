package quic

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"sort"
	"strconv"
	"strings"

	"spip/internal/sanitize"

	"github.com/psanford/tlsfingerprint"
)

// HelloInfo is what is recorded from a QUIC ClientHello.
type HelloInfo struct {
	JA4        string
	JA3        string
	ServerName string
	ALPN       []string
	// HelloRecord is the ClientHello wrapped in a TLS record header, the shape
	// the TCP path stores, so fingerprints can be recomputed from either.
	HelloRecord []byte

	TransportParamsHex  string
	TransportParamsStr  string
	TransportParamsHash string
	UserAgent           string
}

// TransportParam is one QUIC transport parameter (RFC 9000 section 18).
type TransportParam struct {
	ID    uint64
	Value []byte
}

const (
	extServerName      = 0x0000
	extQUICParams      = 0x0039
	extQUICParamsDraft = 0xffa5

	tpInitialSourceCID = 0x0f
	tpVersionInfo      = 0x11
	tpVersionInfoDraft = 0xff73db
	tpUserAgent        = 0x3129

	maxServerName = 255
	maxUserAgent  = 256
	maxParams     = 128
	maxALPN       = 16
)

// Integer parameters whose values reflect implementation defaults.
var tpIntegers = map[uint64]bool{
	0x01: true, 0x03: true, 0x04: true, 0x05: true, 0x06: true, 0x07: true,
	0x08: true, 0x09: true, 0x0a: true, 0x0b: true, 0x0e: true, 0x20: true,
	0xff04de1b: true, // min_ack_delay
}

// ParseHello reads a complete ClientHello handshake message and computes the
// QUIC fingerprints.
func ParseHello(msg []byte) (*HelloInfo, error) {
	if len(msg) < 4 || msg[0] != 0x01 {
		return nil, errors.New("not a ClientHello")
	}
	if len(msg) > 0xffff {
		return nil, errors.New("ClientHello larger than one TLS record")
	}
	rec := make([]byte, 0, 5+len(msg))
	rec = append(rec, 0x16, 0x03, 0x01, byte(len(msg)>>8), byte(len(msg)))
	rec = append(rec, msg...)

	fp, err := tlsfingerprint.ParseClientHello(rec)
	if err != nil {
		return nil, err
	}
	h := &HelloInfo{HelloRecord: rec, JA3: fp.JA3Hash(), JA4: fp.JA4String()}
	if strings.HasPrefix(h.JA4, "t") {
		h.JA4 = "q" + h.JA4[1:] // JA4 protocol marker for QUIC
	}
	for i, p := range fp.ALPNProtocols {
		if i == maxALPN {
			break
		}
		h.ALPN = append(h.ALPN, sanitize.Printable([]byte(p), 32))
	}

	exts, err := helloExtensions(msg[4:])
	if err != nil {
		return h, nil
	}
	h.ServerName = parseSNI(exts[extServerName])
	tp, ok := exts[extQUICParams]
	if !ok {
		tp, ok = exts[extQUICParamsDraft]
	}
	if !ok {
		return h, nil
	}
	h.TransportParamsHex = hex.EncodeToString(tp)
	params, err := parseTransportParams(tp)
	if err != nil {
		return h, nil
	}
	h.TransportParamsStr = describeParams(params)
	sum := sha256.Sum256([]byte(h.TransportParamsStr))
	h.TransportParamsHash = hex.EncodeToString(sum[:6])
	for _, p := range params {
		if p.ID == tpUserAgent && sanitize.IsPrintable(p.Value, maxUserAgent) {
			h.UserAgent = string(p.Value)
		}
	}
	return h, nil
}

func helloExtensions(b []byte) (map[uint16][]byte, error) {
	errShort := errors.New("truncated ClientHello")
	off := 2 + 32 // legacy_version, random
	if len(b) < off+1 {
		return nil, errShort
	}
	off += 1 + int(b[off]) // session id
	if len(b) < off+2 {
		return nil, errShort
	}
	off += 2 + int(binary.BigEndian.Uint16(b[off:])) // cipher suites
	if len(b) < off+1 {
		return nil, errShort
	}
	off += 1 + int(b[off]) // compression methods
	if len(b) < off+2 {
		return nil, errShort
	}
	end := off + 2 + int(binary.BigEndian.Uint16(b[off:]))
	off += 2
	if end > len(b) {
		return nil, errShort
	}
	out := map[uint16][]byte{}
	for off+4 <= end {
		t := binary.BigEndian.Uint16(b[off:])
		n := int(binary.BigEndian.Uint16(b[off+2:]))
		off += 4
		if off+n > end {
			return out, errShort
		}
		if _, dup := out[t]; !dup {
			out[t] = b[off : off+n]
		}
		off += n
	}
	return out, nil
}

func parseSNI(b []byte) string {
	if len(b) < 2 {
		return ""
	}
	for off := 2; off+3 <= len(b); {
		typ, n := b[off], int(binary.BigEndian.Uint16(b[off+1:]))
		off += 3
		if off+n > len(b) {
			return ""
		}
		if typ == 0 {
			if sanitize.IsPrintable(b[off:off+n], maxServerName) {
				return string(b[off : off+n])
			}
			return ""
		}
		off += n
	}
	return ""
}

func parseTransportParams(b []byte) ([]TransportParam, error) {
	var out []TransportParam
	for len(b) > 0 {
		if len(out) == maxParams {
			return out, errors.New("too many transport parameters")
		}
		id, n1, err := readVarint(b)
		if err != nil {
			return out, err
		}
		ln, n2, err := readVarint(b[n1:])
		if err != nil {
			return out, err
		}
		start := n1 + n2
		if ln > uint64(len(b)-start) {
			return out, errors.New("transport parameter beyond extension")
		}
		end := start + int(ln)
		out = append(out, TransportParam{ID: id, Value: b[start:end]})
		b = b[end:]
	}
	return out, nil
}

func isGreaseParam(id uint64) bool { return id >= 27 && (id-27)%31 == 0 }

// describeParams is the input to the transport parameter hash: sorted by id,
// GREASE collapsed, integer values kept, and per-connection or per-build values
// reduced to their presence.
func describeParams(params []TransportParam) string {
	type item struct {
		id  uint64
		txt string
	}
	items := make([]item, 0, len(params))
	grease := false
	for _, p := range params {
		if isGreaseParam(p.ID) {
			grease = true
			continue
		}
		txt := strconv.FormatUint(p.ID, 16)
		switch {
		case tpIntegers[p.ID]:
			if v, n, err := readVarint(p.Value); err == nil && n == len(p.Value) {
				txt += "=" + strconv.FormatUint(v, 10)
			} else {
				txt += "=?"
			}
		case p.ID == tpVersionInfo || p.ID == tpVersionInfoDraft:
			txt += "=" + describeVersions(p.Value)
		case p.ID == tpInitialSourceCID:
			txt += "/" + strconv.Itoa(len(p.Value))
		}
		items = append(items, item{p.ID, txt})
	}
	sort.Slice(items, func(i, j int) bool { return items[i].id < items[j].id })
	parts := make([]string, 0, len(items)+1)
	for _, it := range items {
		parts = append(parts, it.txt)
	}
	if grease {
		parts = append(parts, "grease")
	}
	return strings.Join(parts, ",")
}

// describeVersions renders version_information (RFC 9368) as chosen version
// then offered versions. Reserved GREASE versions, which some clients pick at
// random per connection, are replaced by a single marker.
func describeVersions(v []byte) string {
	if len(v) < 4 || len(v)%4 != 0 || len(v) > 64 {
		return "?" + strconv.Itoa(len(v))
	}
	isGrease := func(x uint32) bool { return x&0x0f0f0f0f == 0x0a0a0a0a }
	name := func(x uint32) string {
		switch x {
		case Version1:
			return "1"
		case Version2:
			return "2"
		}
		return strconv.FormatUint(uint64(x), 16)
	}
	chosen := binary.BigEndian.Uint32(v)
	grease := isGrease(chosen)
	parts := []string{name(chosen)}
	for i := 4; i < len(v); i += 4 {
		x := binary.BigEndian.Uint32(v[i:])
		if isGrease(x) {
			grease = true
			continue
		}
		parts = append(parts, name(x))
	}
	if grease {
		parts = append(parts, "grease")
	}
	return strings.Join(parts, ";")
}
