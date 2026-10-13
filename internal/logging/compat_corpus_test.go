package logging

import (
	"encoding/hex"

	"spip/internal/dnsinfo"
)

// compatCase is one input of the compatibility corpus. testdata/
// compat_golden.jsonl holds the document each of these produced before the
// HTTP request line accepted any RFC 9110 method, repeated headers were
// joined, http.version, ecs.version and millisecond timestamps were added.
// The corpus must not change without regenerating that file from the code it
// was taken from, so cases are only ever appended.
type compatCase struct {
	name string
	// parsedBefore marks inputs whose document is expected to be unchanged
	// apart from the two fields every HTTP or every document now gains.
	parsedBefore bool
	// joined lists header keys that repeat in the input, so their value in
	// http.request.headers is expected to grow.
	joined []string
	data   ConnectionData
}

const compatTS = 1760000000 // 2025-10-09T08:53:20Z

func compatBase(payload string) ConnectionData {
	return ConnectionData{
		Timestamp:       compatTS,
		Payload:         payload,
		PayloadHex:      hex.EncodeToString([]byte(payload)),
		SourceIP:        "198.51.100.7",
		SourcePort:      40000,
		DestinationIP:   "192.0.2.10",
		DestinationPort: 80,
		SessionID:       "compat-session",
	}
}

func compatCorpus() []compatCase {
	var cases []compatCase
	add := func(name string, parsedBefore bool, d ConnectionData, joined ...string) {
		cases = append(cases, compatCase{name: name, parsedBefore: parsedBefore, joined: joined, data: d})
	}

	// Requests the seven-method pattern already parsed.
	d := compatBase("GET / HTTP/1.1\r\nHost: example.com\r\nUser-Agent: curl/8.5.0\r\nAccept: */*\r\n\r\n")
	add("get with host and user agent", true, d)

	d = compatBase("POST /cgi-bin/luci HTTP/1.1\r\nHost: 192.0.2.10:8080\r\nUser-Agent: Mozilla/5.0\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 27\r\n\r\nusername=root&password=root")
	add("post with body and host port", true, d)

	d = compatBase("HEAD /robots.txt HTTP/1.0\r\n\r\n")
	add("head http/1.0 terminator only", true, d)

	d = compatBase("OPTIONS * HTTP/1.1\r\nHost: example.org\r\n")
	add("options host without terminator", true, d)

	d = compatBase("GET /tls HTTP/1.1")
	d.IsTLS = true
	d.TLSALPN = "http/1.1"
	d.TLSServerName = "example.net"
	d.TLSSupportedProtocols = []string{"http/1.1"}
	d.TLSJA4 = "t13d1516h2_8daaf6152771_e5627efa2ab1"
	add("get admitted by alpn alone", true, d)

	d = compatBase("PUT /upload HTTP/1.1\r\nHost: [2001:db8::1]:8443\r\n\r\nPAYLOAD")
	add("put with bracketed ipv6 host and port", true, d)

	d = compatBase("DELETE /x HTTP/1.1\r\nHost: a.example\r\nX-Empty:\r\nnot a header line\r\n: no name\r\n\r\n")
	add("delete with empty and malformed header lines", true, d)

	d = compatBase("PATCH /api HTTP/1.1\r\nHOST: Mixed.Example\r\nuser-AGENT: Tool/1\r\nX-Forwarded-For: 203.0.113.9\r\n\r\n{\"a\":1}")
	add("patch with mixed case header names", true, d)

	d = compatBase("GET\t/tab\tHTTP/1.1\r\nHost: tab.example\r\n\r\n")
	add("tab separated request line", true, d)

	d = compatBase("GET /h2 HTTP/1.1\r\nHost: x\r\n\r\n")
	d.IsTLS = true
	d.TLSALPN = "h2"
	d.TLSVersion = "1.3"
	d.TLSCipherSuite = "TLS_AES_128_GCM_SHA256"
	d.TLSClientSubject = "CN=client"
	d.TLSClientIssuer = "CN=issuer"
	d.TLSClientNotBefore = 1700000000
	d.TLSClientNotAfter = 1800000000
	d.TLSJA3 = "e7d705a3286e19ea42f587b344ee6865"
	d.TLSClientHelloHex = "160301"
	d.CommunityID = "1:abc123"
	d.SSHHassh = "92674389fa1e47a27ddd8d9b63ecd42b"
	d.DurationMs = 1234
	d.BytesIn = 300
	d.BytesOut = 120
	d.RecordSeq = 2
	d.Name = "sensor-a"
	add("get over tls with every optional field", true, d)

	d = compatBase("GET /?q=%3Cscript%3E&a=1 HTTP/1.1\r\nHost: <b>&amp;\r\nUser-Agent: \"quoted\" <ua>\r\n\r\n")
	add("html characters in path and headers", true, d)

	// Inputs that were never HTTP and must stay that way.
	add("request line without headers", true, compatBase("GET / HTTP/1.1"))
	add("ssh banner", true, compatBase("SSH-2.0-OpenSSH_9.6\r\n"))
	add("binary payload", true, compatBase("\x16\x03\x01\x00\xa5\x01\x00\x00\xa1\x03\x03\xff\xfe"))
	add("empty payload", true, compatBase(""))
	add("redis inline command", true, compatBase("*1\r\n$4\r\nPING\r\n"))
	add("bare lf request", true, compatBase("GET / HTTP/1.1\nHost: x\n\n"))
	add("four field request line", true, compatBase("GET / HTTP/1.1 extra\r\nHost: x\r\n\r\n"))
	add("non token method", true, compatBase("GE(T / HTTP/1.1\r\nHost: x\r\n\r\n"))
	add("rtsp request", true, compatBase("OPTIONS rtsp://192.0.2.10/ RTSP/1.0\r\nCSeq: 1\r\n\r\n"))
	add("sip request", true, compatBase("OPTIONS sip:nm SIP/2.0\r\nVia: SIP/2.0/TCP nm\r\n\r\n"))
	add("http response line", true, compatBase("HTTP/1.1 200 OK\r\nServer: x\r\n\r\n"))

	d = compatBase("")
	d.Transport = "udp"
	d.NetworkProtocol = "dns"
	d.Payload = "query A example.com"
	d.DNS = &dnsinfo.Info{ID: 4660, OpCode: "QUERY", Flags: []string{"RD"},
		Questions: []dnsinfo.Question{{Name: "example.com", Type: "A", Class: "IN"}},
		EDNS:      true, EDNSUDPSize: 4096}
	add("dns query", true, d)

	d = compatBase("")
	d.Transport = "udp"
	d.NetworkProtocol = "quic"
	d.Payload = "QUIC v1 Initial sni=example.com"
	d.IsTLS = true
	d.TLSServerName = "example.com"
	d.QUIC = &QUICData{Version: "1", DCID: "0102", Datagrams: 1, Decrypted: true,
		HelloComplete: true, UserAgent: "quic-ua/1"}
	add("quic initial with user agent", true, d)

	// Requests only the RFC 9110 pattern accepts. Before, they were stored as
	// event.summary alone; every field they had then must keep its value.
	d = compatBase("CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\nUser-Agent: proxy-check\r\n\r\n")
	add("connect", false, d)

	d = compatBase("PROPFIND / HTTP/1.1\r\nHost: dav.example\r\nDepth: 1\r\nContent-Type: text/xml\r\n\r\n<?xml version=\"1.0\"?><propfind xmlns=\"DAV:\"><allprop/></propfind>")
	add("propfind with xml body", false, d)

	add("lowercase method", false, compatBase("get / HTTP/1.1\r\nHost: lower.example\r\n\r\n"))
	add("http/2 preface", false, compatBase("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"))
	add("unknown version", false, compatBase("GET / HTTP/1.2\r\nHost: v.example\r\n\r\n"))
	add("method with extra letters", false, compatBase("GETX / HTTP/1.1\r\nHost: x\r\n\r\n"))
	add("trace", false, compatBase("TRACE / HTTP/1.1\r\nHost: t.example\r\n\r\n"))

	d = compatBase("M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\nMX: 1\r\nST: ssdp:all\r\n\r\n")
	d.Transport = "udp"
	d.DestinationPort = 1900
	add("ssdp search over udp", false, d)

	add("token method without headers", true, compatBase("PROPFIND / HTTP/1.1"))

	// Repeated headers: everything but the joined header values is unchanged,
	// and url.domain and user_agent.original keep the last occurrence.
	d = compatBase("GET /dup HTTP/1.1\r\nHost: first.example\r\nUser-Agent: first-agent\r\nHost: second.example:8080\r\nAccept: */*\r\nUser-Agent: second-agent\r\n\r\n")
	add("repeated host and user agent", true, d, "host", "user-agent")

	return cases
}
