package fingerprint

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"unicode"
)

// HTTPFP computes the HTTP request fingerprint.
// method: HTTP method (e.g. GET, POST) - will be abbreviated to 2 chars.
// version: e.g. "HTTP/1.1" -> "11", "HTTP/2" -> "20".
// headerNamesInOrder: header names in the order they appeared in the request (for hash).
// hasCookie, hasReferer: presence of Cookie and Referer headers.
// acceptLanguage: value of Accept-Language header (first 2 alphanumeric chars used, or "00" if empty).
func HTTPFP(method, version string, headerNamesInOrder []string, hasCookie, hasReferer bool, acceptLanguage string) string {
	m := method2Chars(method)
	v := version2Chars(version)
	c := "n"
	if hasCookie {
		c = "c"
	}
	r := "n"
	if hasReferer {
		r = "r"
	}
	// Header count: exclude Cookie and Referer
	count := 0
	for _, n := range headerNamesInOrder {
		lower := strings.ToLower(n)
		if lower != "cookie" && lower != "referer" {
			count++
		}
	}
	if count > 99 {
		count = 99
	}
	countStr := fmt.Sprintf("%02d", count)
	lang := lang2Chars(acceptLanguage)
	hashPart := headerHash(headerNamesInOrder)
	return m + v + c + r + countStr + lang + "_" + hashPart
}

func method2Chars(method string) string {
	switch strings.ToUpper(method) {
	case "GET":
		return "ge"
	case "POST":
		return "po"
	case "PUT":
		return "pu"
	case "DELETE":
		return "de"
	case "HEAD":
		return "he"
	case "OPTIONS":
		return "op"
	case "PATCH":
		return "pa"
	default:
		if len(method) >= 2 {
			return strings.ToLower(method[:2])
		}
		if len(method) == 1 {
			return strings.ToLower(method) + "0"
		}
		return "00"
	}
}

func version2Chars(version string) string {
	// HTTP/1.0 -> 10, HTTP/1.1 -> 11, HTTP/2 -> 20, HTTP/3 -> 30
	if strings.Contains(version, "1.1") {
		return "11"
	}
	if strings.Contains(version, "1.0") {
		return "10"
	}
	if strings.Contains(version, "2") {
		return "20"
	}
	if strings.Contains(version, "3") {
		return "30"
	}
	return "00"
}

func lang2Chars(acceptLanguage string) string {
	s := strings.TrimSpace(acceptLanguage)
	if s == "" {
		return "00"
	}
	// First two alphanumeric characters (e.g. "en" from "en-US")
	var runes []rune
	for _, r := range s {
		if unicode.IsLetter(r) || unicode.IsDigit(r) {
			runes = append(runes, r)
			if len(runes) >= 2 {
				return strings.ToLower(string(runes[0]) + string(runes[1]))
			}
		}
	}
	if len(runes) == 1 {
		return strings.ToLower(string(runes[0]) + string(runes[0]))
	}
	return "00"
}

func headerHash(headerNamesInOrder []string) string {
	if len(headerNamesInOrder) == 0 {
		return "000000000000"
	}
	// SHA256 of header names in order (comma-separated or similar - spec says "all header names in their request order")
	// Common interpretation: concatenate header names (e.g. with comma) and hash
	h := sha256.New()
	for i, n := range headerNamesInOrder {
		if i > 0 {
			h.Write([]byte(","))
		}
		h.Write([]byte(strings.ToLower(n)))
	}
	sum := h.Sum(nil)
	return hex.EncodeToString(sum)[:12]
}
