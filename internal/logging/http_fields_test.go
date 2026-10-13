package logging

import (
	"encoding/json"
	"io"
	"strings"
	"testing"
	"time"
)

func emitDoc(t *testing.T, d ConnectionData) map[string]interface{} {
	t.Helper()
	var doc map[string]interface{}
	if err := json.Unmarshal(emitLine(t, d), &doc); err != nil {
		t.Fatalf("decode: %v", err)
	}
	return doc
}

func field(doc map[string]interface{}, path string) interface{} {
	var cur interface{} = doc
	for _, k := range strings.Split(path, ".") {
		m, ok := cur.(map[string]interface{})
		if !ok {
			return nil
		}
		cur = m[k]
	}
	return cur
}

func httpData(payload string) ConnectionData {
	return ConnectionData{
		Timestamp:       1760000000,
		Payload:         payload,
		SourceIP:        "198.51.100.7",
		SourcePort:      40000,
		DestinationIP:   "192.0.2.10",
		DestinationPort: 80,
		SessionID:       "http-session",
	}
}

// Methods outside the seven common ones are HTTP requests too. They get the
// same http.*, url.* and user_agent.* fields, and keep event.summary, which
// they carried when they were not parsed.
func TestLogConnection_TokenMethods(t *testing.T) {
	cases := []struct {
		name    string
		payload string
		want    map[string]interface{}
	}{
		{
			name:    "connect",
			payload: "CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\nUser-Agent: proxy-check/1\r\n\r\n",
			want: map[string]interface{}{
				"http.request.method":       "CONNECT",
				"http.version":              "1.1",
				"url.path":                  "example.com:443",
				"url.domain":                "example.com",
				"url.port":                  float64(443),
				"user_agent.original":       "proxy-check/1",
				"http.request.headers.host": "example.com:443",
			},
		},
		{
			name:    "webdav propfind",
			payload: "PROPFIND /dav/ HTTP/1.1\r\nHost: dav.example\r\nDepth: 1\r\n\r\n<?xml version=\"1.0\"?><propfind xmlns=\"DAV:\"><allprop/></propfind>",
			want: map[string]interface{}{
				"http.request.method":        "PROPFIND",
				"http.version":               "1.1",
				"url.path":                   "/dav/",
				"url.domain":                 "dav.example",
				"http.request.headers.depth": "1",
				"http.request.body.content":  "<?xml version=\"1.0\"?><propfind xmlns=\"DAV:\"><allprop/></propfind>",
			},
		},
		{
			name:    "lowercase method kept as sent",
			payload: "get /lower HTTP/1.0\r\nHost: lower.example\r\n\r\n",
			want: map[string]interface{}{
				"http.request.method": "get",
				"http.version":        "1.0",
				"url.path":            "/lower",
				"url.domain":          "lower.example",
			},
		},
		{
			name:    "trace",
			payload: "TRACE / HTTP/1.1\r\nHost: t.example\r\n\r\n",
			want:    map[string]interface{}{"http.request.method": "TRACE", "url.domain": "t.example"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			doc := emitDoc(t, httpData(tc.payload))
			for path, want := range tc.want {
				if got := field(doc, path); got != want {
					t.Errorf("%s = %v, want %v", path, got, want)
				}
			}
			if got := field(doc, "event.summary"); got != tc.payload {
				t.Errorf("event.summary = %q, want the payload", got)
			}
			if field(doc, "http.request.hash.akin") == nil {
				t.Error("no akin fingerprint")
			}
		})
	}

	// The HTTP test after the request line is unchanged: no header
	// terminator, no Host and no HTTP ALPN means it is not treated as HTTP.
	doc := emitDoc(t, httpData("PROPFIND / HTTP/1.1"))
	if doc["http"] != nil || doc["url"] != nil {
		t.Errorf("request line alone was parsed as HTTP: %v", doc)
	}
	if got := field(doc, "event.summary"); got != "PROPFIND / HTTP/1.1" {
		t.Errorf("event.summary = %q", got)
	}

	// The seven common methods still carry no event.summary.
	doc = emitDoc(t, httpData("GET / HTTP/1.1\r\nHost: x\r\n\r\n"))
	if s := field(doc, "event.summary"); s != nil {
		t.Errorf("GET gained event.summary %q", s)
	}
}

// A repeated header keeps every value in http.request.headers, while the
// fields derived from Host and User-Agent keep the last occurrence, which is
// the value they always had.
func TestLogConnection_RepeatedHeaders(t *testing.T) {
	doc := emitDoc(t, httpData("GET /dup HTTP/1.1\r\n"+
		"Host: first.example\r\n"+
		"User-Agent: first-agent/1\r\n"+
		"Accept: */*\r\n"+
		"host: second.example:8080\r\n"+
		"User-Agent: second-agent/2\r\n"+
		"X-Forwarded-For: 203.0.113.1\r\n"+
		"X-Forwarded-For: 203.0.113.2\r\n"+
		"X-Forwarded-For: 203.0.113.3\r\n\r\n"))

	checks := map[string]interface{}{
		"http.request.headers.host":            "first.example, second.example:8080",
		"http.request.headers.user-agent":      "first-agent/1, second-agent/2",
		"http.request.headers.x-forwarded-for": "203.0.113.1, 203.0.113.2, 203.0.113.3",
		"http.request.headers.accept":          "*/*",
		"url.domain":                           "second.example",
		"url.port":                             float64(8080),
		"user_agent.original":                  "second-agent/2",
	}
	for path, want := range checks {
		if got := field(doc, path); got != want {
			t.Errorf("%s = %v, want %v", path, got, want)
		}
	}

	// A last Host that is empty leaves url.domain out, as it did before.
	doc = emitDoc(t, httpData("GET / HTTP/1.1\r\nHost: a.example\r\nHost:\r\n\r\n"))
	if got := field(doc, "http.request.headers.host"); got != "a.example, " {
		t.Errorf("headers.host = %q", got)
	}
	if got := field(doc, "url.domain"); got != nil {
		t.Errorf("url.domain = %v, want none", got)
	}
}

func TestLogConnection_HTTPVersion(t *testing.T) {
	for payload, want := range map[string]string{
		"GET / HTTP/1.1\r\nHost: x\r\n\r\n":   "1.1",
		"HEAD / HTTP/1.0\r\n\r\n":             "1.0",
		"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n":    "2.0",
		"GET / HTTP/1.2\r\nHost: x\r\n\r\n":   "1.2",
		"POST /x HTTP/1.1\r\nHost: y\r\n\r\n": "1.1",
	} {
		doc := emitDoc(t, httpData(payload))
		if got := field(doc, "http.version"); got != want {
			t.Errorf("%q: http.version = %v, want %q", payload, got, want)
		}
	}
	if doc := emitDoc(t, httpData("SSH-2.0-x\r\n")); doc["http"] != nil {
		t.Error("non-HTTP payload has an http object")
	}
}

func TestLogConnection_TimestampMilliseconds(t *testing.T) {
	cases := []struct {
		name string
		sec  int64
		ms   int64
		want string
	}{
		{"milliseconds", 1760000000, 1760000000123, "2025-10-09T08:53:20.123Z"},
		{"trailing zero trimmed", 1760000000, 1760000000120, "2025-10-09T08:53:20.12Z"},
		{"whole second", 1760000000, 1760000000000, "2025-10-09T08:53:20Z"},
		{"no milliseconds supplied", 1760000000, 0, "2025-10-09T08:53:20Z"},
		{"milliseconds from another second are not used", 1760000000, 1760000001500, "2025-10-09T08:53:20Z"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			d := httpData("x")
			d.Timestamp, d.TimestampMs = tc.sec, tc.ms
			doc := emitDoc(t, d)
			got, _ := doc["@timestamp"].(string)
			if got != tc.want {
				t.Fatalf("@timestamp = %q, want %q", got, tc.want)
			}
			parsed, err := time.Parse(time.RFC3339Nano, got)
			if err != nil {
				t.Fatalf("parse: %v", err)
			}
			if parsed.Unix() != tc.sec {
				t.Errorf("second = %d, want %d", parsed.Unix(), tc.sec)
			}
		})
	}

	// The document sent on the ECS channel carries the same value.
	ch := make(chan map[string]interface{}, 1)
	d := httpData("x")
	d.TimestampMs = 1760000000999
	if err := NewLoggerWithECSChannel(io.Discard, ch).LogConnection(&d); err != nil {
		t.Fatal(err)
	}
	if got := (<-ch)["@timestamp"]; got != "2025-10-09T08:53:20.999Z" {
		t.Errorf("channel @timestamp = %v", got)
	}
}

func TestLogConnection_ECSVersion(t *testing.T) {
	if ECSVersion != "8.11.0" {
		t.Fatalf("ECSVersion = %q", ECSVersion)
	}
	udp := httpData("raw")
	udp.Transport = "udp"
	for name, d := range map[string]ConnectionData{
		"http":     httpData("GET / HTTP/1.1\r\nHost: x\r\n\r\n"),
		"non-http": httpData("SSH-2.0-x\r\n"),
		"empty":    httpData(""),
		"udp":      udp,
	} {
		if got := field(emitDoc(t, d), "ecs.version"); got != "8.11.0" {
			t.Errorf("%s: ecs.version = %v", name, got)
		}
	}
}
