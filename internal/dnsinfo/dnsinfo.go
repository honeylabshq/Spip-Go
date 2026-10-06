// Package dnsinfo decodes DNS messages received by the sensor. Nothing is
// answered; the question and EDNS shape identify what a scanner looked for.
package dnsinfo

import (
	"encoding/binary"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"spip/internal/sanitize"

	"golang.org/x/net/dns/dnsmessage"
)

const (
	MaxQuestions   = 4
	maxEDNSOptions = 16
	maxNameBytes   = 255
	maxRecords     = 32
	maxTrailing    = 4
)

// ErrNotDNS means the datagram is not a well-formed DNS message.
var ErrNotDNS = errors.New("not a DNS message")

// Question is one entry of the question section.
type Question struct {
	Name  string // no trailing dot; non-printable bytes escaped as \xNN
	Type  string
	Class string
}

// Info is the decoded message.
type Info struct {
	ID         uint16
	Response   bool   // QR bit; a response arriving unasked is backscatter
	OpCode     string // "QUERY", "IQUERY", "STATUS", "NOTIFY", "UPDATE" or a number
	RCode      string // only meaningful on responses
	Flags      []string
	Questions  []Question
	Answers    int
	Authority  int
	Additional int

	EDNS        bool
	EDNSUDPSize uint16
	EDNSVersion uint8
	EDNSDO      bool
	EDNSOptions []int

	// Trailing counts bytes after the message: zeros, CR or LF that some
	// probing tools append. It identifies the tool, not the question.
	Trailing int

	// NetBIOS is set for a NetBIOS name service packet (RFC 1002). It shares
	// the DNS wire format but names a NetBIOS name, not a domain.
	NetBIOS *NetBIOS
}

// NetBIOS is the decoded first question of a NetBIOS name service packet.
type NetBIOS struct {
	Name   string // "*" for the wildcard used by node status probes
	Suffix uint8  // the 16th byte: the service type
	Type   string // "NB" (name query) or "NBSTAT" (node status)
}

// Parse decodes b as a DNS message. It fails unless b is exactly one message
// (header, at least one question, and every record the counts announce,
// ending at the last byte) with a valid opcode, question type and class.
// Binary probes for other services often begin with twelve bytes that read as
// a DNS header; framing the whole datagram is what tells them apart.
func Parse(b []byte) (*Info, error) {
	end := framedLen(b)
	if end < 0 || !padding(b[end:]) {
		return nil, ErrNotDNS
	}
	var p dnsmessage.Parser
	h, err := p.Start(b)
	if err != nil {
		return nil, err
	}
	switch h.OpCode {
	case 0, 1, 2, 4, 5: // QUERY, IQUERY, STATUS, NOTIFY, UPDATE
	default:
		return nil, ErrNotDNS
	}
	info := &Info{
		Trailing: len(b) - end,
		ID:       h.ID,
		Response: h.Response,
		OpCode:   opCodeName(h.OpCode),
		RCode:    rcodeName(h.RCode),
	}
	for _, f := range []struct {
		on   bool
		name string
	}{
		{h.Authoritative, "AA"}, {h.Truncated, "TC"}, {h.RecursionDesired, "RD"},
		{h.RecursionAvailable, "RA"}, {h.AuthenticData, "AD"}, {h.CheckingDisabled, "CD"},
	} {
		if f.on {
			info.Flags = append(info.Flags, f.name)
		}
	}

	qs, err := p.AllQuestions()
	if err != nil {
		return nil, fmt.Errorf("questions: %w", err)
	}
	for _, q := range qs {
		if q.Type == 0 || !validClass(q.Class) {
			return nil, ErrNotDNS
		}
	}
	for i, q := range qs {
		if i == MaxQuestions {
			break
		}
		info.Questions = append(info.Questions, Question{
			Name:  displayName(q.Name),
			Type:  typeName(q.Type),
			Class: className(q.Class),
		})
	}

	if nb := netBIOS(qs[0]); nb != nil {
		info.NetBIOS = nb
		info.Questions[0].Name, info.Questions[0].Type = nb.Name, nb.Type
	}

	// A record whose content does not decode ends the walk but keeps the
	// query; its framing was already checked above.
	if n, err := countSection(&p, p.AnswerHeader, p.SkipAnswer); err == nil {
		info.Answers = n
	} else {
		return info, nil
	}
	if n, err := countSection(&p, p.AuthorityHeader, p.SkipAuthority); err == nil {
		info.Authority = n
	} else {
		return info, nil
	}
	for {
		rh, err := p.AdditionalHeader()
		if err != nil {
			break
		}
		info.Additional++
		if rh.Type == dnsmessage.TypeOPT {
			info.EDNS = true
			info.EDNSUDPSize = uint16(rh.Class)
			info.EDNSVersion = uint8(rh.TTL >> 16)
			info.EDNSDO = rh.TTL&(1<<15) != 0
			res, err := p.OPTResource()
			if err != nil {
				break
			}
			for _, o := range res.Options {
				if len(info.EDNSOptions) < maxEDNSOptions {
					info.EDNSOptions = append(info.EDNSOptions, int(o.Code))
				}
			}
			continue
		}
		if err := p.SkipAdditional(); err != nil {
			break
		}
	}
	return info, nil
}

func countSection(p *dnsmessage.Parser, header func() (dnsmessage.ResourceHeader, error), skip func() error) (int, error) {
	n := 0
	for {
		if _, err := header(); err != nil {
			if err == dnsmessage.ErrSectionDone {
				return n, nil
			}
			return n, err
		}
		if err := skip(); err != nil {
			return n, err
		}
		n++
	}
}

// framedLen returns the length of the DNS message at the start of b, or -1
// unless the header, the questions and every record its counts announce fit.
func framedLen(b []byte) int {
	if len(b) < 12 {
		return -1
	}
	qd := int(binary.BigEndian.Uint16(b[4:]))
	rr := int(binary.BigEndian.Uint16(b[6:])) + int(binary.BigEndian.Uint16(b[8:])) + int(binary.BigEndian.Uint16(b[10:]))
	if qd < 1 || qd > MaxQuestions || rr > maxRecords {
		return -1
	}
	off := 12
	for i := 0; i < qd; i++ {
		if off = skipName(b, off); off < 0 || off+4 > len(b) {
			return -1
		}
		off += 4
	}
	for i := 0; i < rr; i++ {
		if off = skipName(b, off); off < 0 || off+10 > len(b) {
			return -1
		}
		off += 10 + int(binary.BigEndian.Uint16(b[off+8:]))
		if off > len(b) {
			return -1
		}
	}
	return off
}

// padding accepts what probing tools have been seen to append after a
// message: at most a few zero, CR or LF bytes.
func padding(t []byte) bool {
	if len(t) > maxTrailing {
		return false
	}
	for _, c := range t {
		if c != 0 && c != '\r' && c != '\n' {
			return false
		}
	}
	return true
}

// skipName returns the offset after the name at off, or -1. A compression
// pointer must point back into the message, before the name it ends.
func skipName(b []byte, off int) int {
	start, total := off, 0
	for {
		if off >= len(b) {
			return -1
		}
		c := int(b[off])
		switch {
		case c == 0:
			return off + 1
		case c&0xC0 == 0xC0:
			if off+1 >= len(b) {
				return -1
			}
			if ptr := (c&0x3F)<<8 | int(b[off+1]); ptr < 12 || ptr >= start {
				return -1
			}
			return off + 2
		case c&0xC0 != 0:
			return -1
		}
		if total += c + 1; total > maxNameBytes {
			return -1
		}
		off += 1 + c
	}
}

// validClass accepts IN, CH, HS, NONE and ANY. The top bit is mDNS's
// unicast-response flag, not part of the class.
func validClass(c dnsmessage.Class) bool {
	switch c & 0x7fff {
	case 1, 3, 4, 254, 255:
		return true
	}
	return false
}

// netBIOS decodes a NetBIOS name service question: a 32-character first
// label in RFC 1001 first-level encoding (each byte as two letters A-P),
// type NB (0x20) or NBSTAT (0x21), class IN.
func netBIOS(q dnsmessage.Question) *NetBIOS {
	if q.Class&0x7fff != 1 || (q.Type != 0x20 && q.Type != 0x21) {
		return nil
	}
	label, _, _ := strings.Cut(string(q.Name.Data[:q.Name.Length]), ".")
	if len(label) != 32 {
		return nil
	}
	raw := make([]byte, 16)
	for i := 0; i < 16; i++ {
		hi, lo := label[2*i]-'A', label[2*i+1]-'A'
		if hi > 15 || lo > 15 {
			return nil
		}
		raw[i] = hi<<4 | lo
	}
	nb := &NetBIOS{Suffix: raw[15], Type: "NB"}
	if q.Type == 0x21 {
		nb.Type = "NBSTAT"
	}
	if raw[0] == '*' {
		nb.Name = "*"
	} else {
		nb.Name = sanitize.Printable([]byte(strings.TrimRight(string(raw[:15]), " ")), 15)
	}
	return nb
}

// Summary is the one-line text stored as event.summary.
func (i *Info) Summary() string {
	if nb := i.NetBIOS; nb != nil {
		if nb.Type == "NBSTAT" {
			return "NetBIOS node status query " + nb.Name
		}
		return fmt.Sprintf("NetBIOS name query %s<%02x>", nb.Name, nb.Suffix)
	}
	kind := "query"
	if i.Response {
		kind = "response"
	}
	var b strings.Builder
	b.WriteString("DNS ")
	b.WriteString(kind)
	if i.OpCode != "QUERY" {
		b.WriteString(" " + i.OpCode)
	}
	for _, q := range i.Questions {
		b.WriteString(" ")
		b.WriteString(q.Type)
		if q.Class != "IN" {
			b.WriteString("/" + q.Class)
		}
		b.WriteString(" ")
		if q.Name == "" {
			b.WriteString(".")
		} else {
			b.WriteString(q.Name)
		}
	}
	return b.String()
}

func displayName(n dnsmessage.Name) string {
	b := n.Data[:min(int(n.Length), len(n.Data))]
	return strings.TrimSuffix(sanitize.Printable(b, maxNameBytes), ".")
}

func typeName(t dnsmessage.Type) string {
	switch t {
	case dnsmessage.TypeA:
		return "A"
	case dnsmessage.TypeNS:
		return "NS"
	case dnsmessage.TypeCNAME:
		return "CNAME"
	case dnsmessage.TypeSOA:
		return "SOA"
	case dnsmessage.TypePTR:
		return "PTR"
	case dnsmessage.TypeMX:
		return "MX"
	case dnsmessage.TypeTXT:
		return "TXT"
	case dnsmessage.TypeAAAA:
		return "AAAA"
	case dnsmessage.TypeSRV:
		return "SRV"
	case dnsmessage.TypeOPT:
		return "OPT"
	case dnsmessage.TypeWKS:
		return "WKS"
	case dnsmessage.TypeHINFO:
		return "HINFO"
	case dnsmessage.TypeMINFO:
		return "MINFO"
	case dnsmessage.TypeAXFR:
		return "AXFR"
	case dnsmessage.TypeALL:
		return "ANY"
	}
	switch uint16(t) {
	case 43:
		return "DS"
	case 46:
		return "RRSIG"
	case 48:
		return "DNSKEY"
	case 64:
		return "SVCB"
	case 65:
		return "HTTPS"
	case 251:
		return "IXFR"
	case 257:
		return "CAA"
	}
	return "TYPE" + strconv.Itoa(int(t))
}

func className(c dnsmessage.Class) string {
	switch uint16(c) {
	case 1:
		return "IN"
	case 3:
		return "CH"
	case 4:
		return "HS"
	case 255:
		return "ANY"
	}
	return "CLASS" + strconv.Itoa(int(c))
}

func opCodeName(o dnsmessage.OpCode) string {
	switch o {
	case 0:
		return "QUERY"
	case 1:
		return "IQUERY"
	case 2:
		return "STATUS"
	case 4:
		return "NOTIFY"
	case 5:
		return "UPDATE"
	}
	return strconv.Itoa(int(o))
}

func rcodeName(r dnsmessage.RCode) string {
	switch r {
	case 0:
		return "NOERROR"
	case 1:
		return "FORMERR"
	case 2:
		return "SERVFAIL"
	case 3:
		return "NXDOMAIN"
	case 4:
		return "NOTIMP"
	case 5:
		return "REFUSED"
	}
	return strconv.Itoa(int(r))
}
