package dnsinfo

import (
	"strings"
	"testing"
)

func FuzzParse(f *testing.F) {
	f.Add([]byte("\xab\xcd\x01\x20\x00\x01\x00\x00\x00\x00\x00\x01\x07example\x03com\x00\x00\x01\x00\x01\x00\x00\x29\x04\xd0\x00\x00\x00\x00\x00\x00"))
	f.Add([]byte("\x00\x01\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07version\x04bind\x00\x00\x10\x00\x03"))
	f.Fuzz(func(t *testing.T, b []byte) {
		info, err := Parse(b)
		if err != nil {
			return
		}
		if len(info.Questions) > MaxQuestions || len(info.EDNSOptions) > maxEDNSOptions {
			t.Fatal("bounds exceeded")
		}
		for _, q := range info.Questions {
			for _, c := range []byte(q.Name) {
				if c < 0x20 || c > 0x7e {
					t.Fatalf("unescaped byte 0x%02x in %q", c, q.Name)
				}
			}
		}
		_ = strings.TrimSpace(info.Summary())
	})
}
