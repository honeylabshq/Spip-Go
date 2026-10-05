package quic

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/psanford/tlsfingerprint"
)

// HelloInfo is what the sensor records from a QUIC ClientHello.
type HelloInfo struct {
	JA4        string   // JA4 with the QUIC protocol prefix "q"
	JA3        string   // JA3 hash, for feeds that still key on it
	ServerName string   // SNI host name, if sent
	ALPN       []string // offered application protocols ("h3", "doq", ...)
	// HelloRecord is the ClientHello wrapped in a TLS handshake record header,
	// the same shape the TCP path stores in tls.client.hello_hex, so one
	// consumer can recompute fingerprints from either transport.
	HelloRecord []byte

	TransportParams     []TransportParam
	TransportParamsHex  string // raw quic_transport_parameters extension body
	TransportParamsStr  string // normalised description that the hash covers
	TransportParamsHash string // first 12 hex characters of SHA-256 over TransportParamsStr
	// UserAgent is the value of Google's user_agent transport parameter
	// (0x3129), which some Chromium builds send.
	UserAgent string
}

// TransportParam is one QUIC transport parameter (RFC 9000 section 18).
type TransportParam struct {
	ID    uint64
	Value []byte
}

const (
	extServerName      = 0x0000
	extALPN            = 0x0010
	extQUICParams      = 0x0039
	extQUICParamsDraft = 0xffa5
	tpUserAgent        = 0x3129
	tpInitialSourceCID = 0x0f
	tpVersionInfo      = 0x11
	tpVersionInfoDraft = 0xff73db
)

// tpIntegers are parameters whose value is one varint. Their values describe
// the implementation (default windows, idle timeouts, limits), so they go into
// the fingerprint; quic-go, Chromium, ngtcp2 and msquic each ship different
// defaults.
var tpIntegers = map[uint64]bool{
	0x01:       true, // max_idle_timeout
	0x03:       true, // max_udp_payload_size
	0x04:       true, // initial_max_data
	0x05:       true, // initial_max_stream_data_bidi_local
	0x06:       true, // initial_max_stream_data_bidi_remote
	0x07:       true, // initial_max_stream_data_uni
	0x08:       true, // initial_max_streams_bidi
	0x09:       true, // initial_max_streams_uni
	0x0a:       true, // ack_delay_exponent
	0x0b:       true, // max_ack_delay
	0x0e:       true, // active_connection_id_limit
	0x20:       true, // max_datagram_frame_size
	0xff04de1b: true, // min_ack_delay (draft-ietf-quic-ack-frequency)
}

// ParseHello reads a complete ClientHello handshake message (as returned in
// Attempt.Hello) and computes the QUIC fingerprints.
func ParseHello(msg []byte) (*HelloInfo, error) {
	if len(msg) < 4 || msg[0] != 0x01 {
		return nil, fmt.Errorf("not a ClientHello")
	}
	if len(msg) > 0xffff {
		return nil, fmt.Errorf("ClientHello larger than one TLS record")
	}
	rec := make([]byte, 0, 5+len(msg))
	rec = append(rec, 0x16, 0x03, 0x01, byte(len(msg)>>8), byte(len(msg)))
	rec = append(rec, msg...)

	h := &HelloInfo{HelloRecord: rec}
	fp, err := tlsfingerprint.ParseClientHello(rec)
	if err != nil {
		return nil, fmt.Errorf("fingerprint ClientHello: %w", err)
	}
	// The library hard-codes the TCP prefix; JA4 defines "q" for QUIC and the
	// rest of the string is computed the same way.
	ja4 := fp.JA4String()
	if strings.HasPrefix(ja4, "t") {
		ja4 = "q" + ja4[1:]
	}
	h.JA4 = ja4
	h.JA3 = fp.JA3Hash()
	h.ALPN = fp.ALPNProtocols

	exts, err := helloExtensions(msg[4:])
	if err != nil {
		return h, nil // fingerprints stand; extension details are a bonus
	}
	if sn, ok := exts[extServerName]; ok {
		h.ServerName = parseSNI(sn)
	}
	tp, ok := exts[extQUICParams]
	if !ok {
		tp, ok = exts[extQUICParamsDraft]
	}
	if ok {
		h.TransportParamsHex = hex.EncodeToString(tp)
		if params, err := parseTransportParams(tp); err == nil {
			h.TransportParams = params
			h.TransportParamsStr = describeParams(params)
			sum := sha256.Sum256([]byte(h.TransportParamsStr))
			h.TransportParamsHash = hex.EncodeToString(sum[:])[:12]
			for _, p := range params {
				if p.ID == tpUserAgent && printable(p.Value) {
					h.UserAgent = string(p.Value)
				}
			}
		}
	}
	return h, nil
}

// helloExtensions returns the extension bodies of a ClientHello body.
func helloExtensions(b []byte) (map[uint16][]byte, error) {
	off := 2 + 32 // legacy_version, random
	if len(b) < off+1 {
		return nil, fmt.Errorf("short hello")
	}
	off += 1 + int(b[off]) // session id
	if len(b) < off+2 {
		return nil, fmt.Errorf("short hello")
	}
	off += 2 + int(binary.BigEndian.Uint16(b[off:])) // cipher suites
	if len(b) < off+1 {
		return nil, fmt.Errorf("short hello")
	}
	off += 1 + int(b[off]) // compression methods
	if len(b) < off+2 {
		return nil, fmt.Errorf("no extensions")
	}
	end := off + 2 + int(binary.BigEndian.Uint16(b[off:]))
	off += 2
	if end > len(b) {
		return nil, fmt.Errorf("extensions beyond hello")
	}
	out := map[uint16][]byte{}
	for off+4 <= end {
		t := binary.BigEndian.Uint16(b[off:])
		n := int(binary.BigEndian.Uint16(b[off+2:]))
		off += 4
		if off+n > end {
			return out, fmt.Errorf("extension beyond hello")
		}
		if _, dup := out[t]; !dup {
			out[t] = b[off : off+n]
		}
		off += n
	}
	return out, nil
}

func parseSNI(b []byte) string {
	if len(b) < 5 {
		return ""
	}
	off := 2 // list length
	for off+3 <= len(b) {
		typ := b[off]
		n := int(binary.BigEndian.Uint16(b[off+1:]))
		off += 3
		if off+n > len(b) {
			return ""
		}
		if typ == 0 {
			name := b[off : off+n]
			if printable(name) {
				return string(name)
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
			return out, fmt.Errorf("transport parameter beyond extension")
		}
		out = append(out, TransportParam{ID: id, Value: append([]byte(nil), b[start:start+int(ln)]...)})
		b = b[start+int(ln):]
		if len(out) > 128 {
			return out, fmt.Errorf("too many transport parameters")
		}
	}
	return out, nil
}

// isGreaseParam reports reserved parameter ids of the form 31*N+27, which
// clients send with random ids and random contents (RFC 9000 18.1).
func isGreaseParam(id uint64) bool { return id >= 27 && (id-27)%31 == 0 }

// describeParams builds the string the transport parameter hash covers. It is
// sorted by id so an implementation that shuffles parameters still produces
// one value, collapses GREASE ids to one marker, keeps the values of the
// integer parameters, and drops values that change per connection (the
// initial source connection id) or per sender in ways that say nothing about
// the software.
func describeParams(params []TransportParam) string {
	type item struct {
		id  uint64
		txt string
	}
	var items []item
	grease := 0
	for _, p := range params {
		if isGreaseParam(p.ID) {
			grease++
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
			// Chosen and offered versions are a property of the build.
			txt += "=" + describeVersions(p.Value)
		case p.ID == tpInitialSourceCID:
			txt += fmt.Sprintf("/%d", len(p.Value))
		default:
			// Flags (disable_active_migration, grease_quic_bit) and parameters
			// this code does not decode contribute their id only. Their
			// lengths can vary per connection or per build (Chromium's
			// user_agent carries the version string), which would split one
			// implementation across many hashes.
		}
		items = append(items, item{p.ID, txt})
	}
	sort.Slice(items, func(i, j int) bool { return items[i].id < items[j].id })
	parts := make([]string, 0, len(items)+1)
	for _, it := range items {
		parts = append(parts, it.txt)
	}
	if grease > 0 {
		parts = append(parts, "grease")
	}
	return strings.Join(parts, ",")
}

// describeVersions renders a version_information value (RFC 9368): the chosen
// version, then the offered list. Chromium inserts a reserved GREASE version
// (0x?a?a?a?a) chosen at random per connection and at a random position, which
// split one browser build across a new hash on every connection in the lab on
// 2026-10-05. GREASE entries are dropped and noted once.
func describeVersions(v []byte) string {
	if len(v) < 4 || len(v)%4 != 0 {
		return "?" + strconv.Itoa(len(v))
	}
	name := func(x uint32) string {
		switch x {
		case Version1:
			return "1"
		case Version2:
			return "2"
		}
		return strconv.FormatUint(uint64(x), 16)
	}
	isGrease := func(x uint32) bool { return x&0x0f0f0f0f == 0x0a0a0a0a }
	chosen := binary.BigEndian.Uint32(v)
	parts := []string{}
	grease := isGrease(chosen)
	for i := 4; i < len(v); i += 4 {
		x := binary.BigEndian.Uint32(v[i:])
		if isGrease(x) {
			grease = true
			continue
		}
		parts = append(parts, name(x))
	}
	out := name(chosen) + ";" + strings.Join(parts, ";")
	if grease {
		out += ";grease"
	}
	return out
}

func printable(b []byte) bool {
	if len(b) == 0 || len(b) > 512 {
		return false
	}
	for _, c := range b {
		if c < 0x20 || c > 0x7e {
			return false
		}
	}
	return true
}
