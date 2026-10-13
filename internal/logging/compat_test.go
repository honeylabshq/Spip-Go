package logging

import (
	"bufio"
	"bytes"
	"encoding/json"
	"os"
	"slices"
	"sort"
	"strings"
	"testing"
)

type goldenLine struct {
	Name string `json:"name"`
	Line string `json:"line"`
}

func loadCompatGolden(t *testing.T) []goldenLine {
	t.Helper()
	f, err := os.Open("testdata/compat_golden.jsonl")
	if err != nil {
		t.Fatalf("open golden: %v", err)
	}
	defer f.Close()
	var out []goldenLine
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	for sc.Scan() {
		var g goldenLine
		if err := json.Unmarshal(sc.Bytes(), &g); err != nil {
			t.Fatalf("golden line: %v", err)
		}
		out = append(out, g)
	}
	if err := sc.Err(); err != nil {
		t.Fatalf("read golden: %v", err)
	}
	return out
}

// leaves flattens a document to dotted paths and the exact bytes the encoder
// wrote for each value. Objects are descended into; arrays are leaves.
func leaves(t *testing.T, doc []byte) map[string]string {
	t.Helper()
	out := map[string]string{}
	var walk func(prefix string, raw json.RawMessage)
	walk = func(prefix string, raw json.RawMessage) {
		trimmed := bytes.TrimSpace(raw)
		if len(trimmed) > 0 && trimmed[0] == '{' {
			var m map[string]json.RawMessage
			if err := json.Unmarshal(trimmed, &m); err != nil {
				t.Fatalf("decode %s: %v", prefix, err)
			}
			for k, v := range m {
				p := k
				if prefix != "" {
					p = prefix + "." + k
				}
				walk(p, v)
			}
			return
		}
		out[prefix] = string(trimmed)
	}
	walk("", json.RawMessage(doc))
	return out
}

func emitLine(t *testing.T, d ConnectionData) []byte {
	t.Helper()
	var buf bytes.Buffer
	if err := NewLogger(&buf).LogConnection(&d); err != nil {
		t.Fatalf("LogConnection: %v", err)
	}
	return buf.Bytes()
}

// stripAdded removes the two fields every document (ecs.version) or every
// HTTP document (http.version) now carries and re-encodes the rest. The
// values are kept as the raw bytes the logger wrote.
func stripAdded(t *testing.T, line []byte) []byte {
	t.Helper()
	var top map[string]json.RawMessage
	if err := json.Unmarshal(line, &top); err != nil {
		t.Fatalf("decode: %v", err)
	}
	delete(top, "ecs")
	if raw, ok := top["http"]; ok {
		var h map[string]json.RawMessage
		if err := json.Unmarshal(raw, &h); err != nil {
			t.Fatalf("decode http: %v", err)
		}
		delete(h, "version")
		b, err := json.Marshal(h)
		if err != nil {
			t.Fatalf("encode http: %v", err)
		}
		top["http"] = b
	}
	b, err := json.Marshal(top)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	return append(b, '\n')
}

// TestLogConnection_CompatWithPreviousOutput replays the corpus against the
// documents the logger wrote before this change. Every field that existed
// then must keep the exact bytes it had. A request that parsed then must
// produce the same document byte for byte once ecs.version and http.version
// are taken out. A request that parses only now may add http.*, url.* and
// user_agent.*, and nothing else.
func TestLogConnection_CompatWithPreviousOutput(t *testing.T) {
	golden := loadCompatGolden(t)
	cases := compatCorpus()
	if len(golden) != len(cases) {
		t.Fatalf("golden has %d lines, corpus %d cases: the corpus changed without its golden file", len(golden), len(cases))
	}
	for i, c := range cases {
		g := golden[i]
		if g.Name != c.name {
			t.Fatalf("case %d: golden %q, corpus %q", i, g.Name, c.name)
		}
		t.Run(c.name, func(t *testing.T) {
			got := emitLine(t, c.data)
			old := leaves(t, []byte(g.Line))
			now := leaves(t, got)

			for path, want := range old {
				if key, ok := strings.CutPrefix(path, "http.request.headers."); ok && slices.Contains(c.joined, key) {
					continue // checked below
				}
				if now[path] != want {
					t.Errorf("%s = %s, was %s", path, now[path], want)
				}
			}

			var added []string
			for path := range now {
				if _, ok := old[path]; !ok {
					added = append(added, path)
				}
			}
			sort.Strings(added)
			if now["ecs.version"] != `"8.11.0"` {
				t.Errorf("ecs.version = %s", now["ecs.version"])
			}

			if c.parsedBefore {
				want := []string{"ecs.version"}
				if _, wasHTTP := old["http.request.method"]; wasHTTP {
					want = append(want, "http.version")
				}
				if !slices.Equal(added, want) {
					t.Errorf("added fields %v, want %v", added, want)
				}
				if len(c.joined) == 0 {
					if stripped := stripAdded(t, got); !bytes.Equal(stripped, []byte(g.Line)) {
						t.Errorf("document changed:\n got %s\nwant %s", stripped, g.Line)
					}
				}
			} else {
				for _, p := range added {
					if !strings.HasPrefix(p, "http.") && !strings.HasPrefix(p, "url.") &&
						!strings.HasPrefix(p, "user_agent.") && p != "ecs.version" {
						t.Errorf("unexpected new field %s", p)
					}
				}
				if _, ok := now["http.request.method"]; !ok {
					t.Errorf("not parsed as HTTP: %v", added)
				}
			}

			for _, key := range c.joined {
				path := "http.request.headers." + key
				var oldV, newV string
				_ = json.Unmarshal([]byte(old[path]), &oldV)
				_ = json.Unmarshal([]byte(now[path]), &newV)
				if !strings.HasSuffix(newV, ", "+oldV) {
					t.Errorf("%s = %q, want the joined values ending in the old value %q", path, newV, oldV)
				}
			}
		})
	}
}

// TestHTTPRequestLineIsASuperset checks that every request line the old
// pattern accepted is accepted by the new one with the same three captures,
// so the method, url.path and version of a request that parsed before cannot
// differ.
func TestHTTPRequestLineIsASuperset(t *testing.T) {
	methods := []string{"GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH"}
	targets := []string{"/", "*", "/a?b=c&d=%20", "http://example.com/x", "example.com:443", "/\x7f\xff", "//"}
	seps := []string{" ", "\t", "  ", " \t ", "\f", "\r"}
	versions := []string{"HTTP/1.0", "HTTP/1.1"}
	n := 0
	for _, m := range methods {
		for _, tg := range targets {
			for _, s1 := range seps {
				for _, s2 := range seps {
					for _, v := range versions {
						line := m + s1 + tg + s2 + v
						old := legacyHTTPReqLineRe.FindStringSubmatch(line)
						if old == nil {
							continue
						}
						n++
						now := httpReqLineRe.FindStringSubmatch(line)
						if !slices.Equal(old, now) {
							t.Errorf("%q: old %q, new %q", line, old, now)
						}
					}
				}
			}
		}
	}
	if n == 0 {
		t.Fatal("no line matched the old pattern")
	}

	for _, line := range []string{
		"GET / HTTP/1.1 extra", "GE(T / HTTP/1.1", "GET /", "GET / HTTP/11", "GET / http/1.1",
		"GET / HTTP/1.1\nHost: x", "OPTIONS sip:nm SIP/2.0", "HTTP/1.1 200 OK", " GET / HTTP/1.1",
	} {
		if httpReqLineRe.MatchString(line) {
			t.Errorf("%q must not be a request line", line)
		}
	}
}
