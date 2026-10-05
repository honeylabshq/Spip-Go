// Package dnsinfo decodes DNS messages that arrive at the sensor. Nothing is
// answered: a honeypot that replies to DNS is an open resolver or an
// amplifier. What is recorded is the question a scanner asked, which names the
// thing it was looking for (a reflection test domain, an amplification-friendly
// ANY query, a version.bind probe), and the EDNS shape, which differs between
// tools.
package dnsinfo

import (
	"fmt"
	"strconv"
	"strings"

	"golang.org/x/net/dns/dnsmessage"
)

// MaxQuestions bounds what is kept from one message. Real queries carry one.
const MaxQuestions = 4

// Question is one entry of the question section.
type Question struct {
	Name  string // without the trailing dot, as ECS dns.question.name
	Type  string // "A", "ANY", "TXT", or "TYPE65" for types without a name
	Class string // "IN", "CH" (version.bind), or "CLASS%d"
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

	// EDNS(0) from the OPT record, when present.
	EDNS        bool
	EDNSUDPSize uint16
	EDNSVersion uint8
	EDNSDO      bool  // DNSSEC OK
	EDNSOptions []int // option codes in order (8 client subnet, 10 cookie, ...)
}

// Parse decodes b as a DNS message. It fails unless the header and every
// question parse, which keeps arbitrary binary probes from being labelled DNS
// because their first twelve bytes happen to fit a header.
func Parse(b []byte) (*Info, error) {
	var p dnsmessage.Parser
	h, err := p.Start(b)
	if err != nil {
		return nil, err
	}
	info := &Info{
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
	if !info.Response && len(qs) == 0 {
		return nil, fmt.Errorf("query without a question")
	}
	for i, q := range qs {
		if i == MaxQuestions {
			break
		}
		info.Questions = append(info.Questions, Question{
			Name:  strings.TrimSuffix(q.Name.String(), "."),
			Type:  typeName(q.Type),
			Class: className(q.Class),
		})
	}

	// Count the remaining sections and find the OPT record. A malformed
	// record after the question still leaves a valid query, so errors past
	// this point end the walk without discarding what was decoded.
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
				if len(info.EDNSOptions) < 16 {
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

// Summary is the one-line text stored as event.summary, which is what the
// site's search and payload views show for non-HTTP events.
func (i *Info) Summary() string {
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
