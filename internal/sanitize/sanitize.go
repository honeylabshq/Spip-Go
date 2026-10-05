// Package sanitize renders attacker-supplied bytes as bounded printable text.
package sanitize

import (
	"strconv"
	"strings"
)

// Printable returns b with every byte outside printable ASCII written as
// \xNN, and backslashes doubled so the escaping is unambiguous. The result is
// never longer than max bytes of input.
func Printable(b []byte, max int) string {
	if len(b) > max {
		b = b[:max]
	}
	var sb strings.Builder
	sb.Grow(len(b))
	for _, c := range b {
		switch {
		case c == '\\':
			sb.WriteString(`\\`)
		case c >= 0x20 && c <= 0x7e:
			sb.WriteByte(c)
		default:
			sb.WriteString(`\x`)
			if c < 0x10 {
				sb.WriteByte('0')
			}
			sb.WriteString(strconv.FormatUint(uint64(c), 16))
		}
	}
	return sb.String()
}

// IsPrintable reports whether b is non-empty printable ASCII of at most max bytes.
func IsPrintable(b []byte, max int) bool {
	if len(b) == 0 || len(b) > max {
		return false
	}
	for _, c := range b {
		if c < 0x20 || c > 0x7e {
			return false
		}
	}
	return true
}
