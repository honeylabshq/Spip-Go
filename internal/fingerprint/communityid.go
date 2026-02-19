package fingerprint

import (
	"crypto/sha1"
	"encoding/base64"
	"net"
)

// CommunityIDV1 computes the Community ID v1.0 flow hash (RFC-style).
// 5-tuple: source IP, destination IP, source port, destination port, protocol (e.g. 6 for TCP).
// seed is the optional 2-byte seed (use 0 for default). Endpoints are normalized so the smaller
// IP:port comes first; then SHA1 and Base64 with "1:" prefix.
func CommunityIDV1(sourceIP, destIP string, sourcePort, destPort uint16, protocol uint8, seed uint16) string {
	sip := net.ParseIP(sourceIP)
	dip := net.ParseIP(destIP)
	if sip == nil || dip == nil {
		return ""
	}

	var sipBytes, dipBytes []byte
	if ip4 := sip.To4(); ip4 != nil {
		sipBytes = ip4
	} else {
		sipBytes = sip.To16()
	}
	if ip4 := dip.To4(); ip4 != nil {
		dipBytes = ip4
	} else {
		dipBytes = dip.To16()
	}

	// Normalize: order so smaller endpoint first (compare IP then port, lexicographic)
	sp := make([]byte, len(sipBytes)+2)
	copy(sp, sipBytes)
	sp[len(sipBytes)] = byte(sourcePort >> 8)
	sp[len(sipBytes)+1] = byte(sourcePort)

	dp := make([]byte, len(dipBytes)+2)
	copy(dp, dipBytes)
	dp[len(dipBytes)] = byte(destPort >> 8)
	dp[len(dipBytes)+1] = byte(destPort)

	firstIP, firstPort := sipBytes, sourcePort
	secondIP, secondPort := dipBytes, destPort
	if compareAddrPort(sp, dp) > 0 {
		firstIP, firstPort = dipBytes, destPort
		secondIP, secondPort = sipBytes, sourcePort
	}

	// Seed (2 bytes big-endian) + first IP + second IP + protocol (1 byte) + padding (1 byte) + first port (2) + second port (2)
	h := sha1.New()
	buf := make([]byte, 0, 2+len(firstIP)+len(secondIP)+2+2+2)
	buf = append(buf, byte(seed>>8), byte(seed))
	buf = append(buf, firstIP...)
	buf = append(buf, secondIP...)
	buf = append(buf, protocol, 0)
	buf = append(buf, byte(firstPort>>8), byte(firstPort), byte(secondPort>>8), byte(secondPort))
	h.Write(buf)
	sum := h.Sum(nil)
	return "1:" + base64.StdEncoding.EncodeToString(sum)
}

// compareAddrPort returns -1 if a < b, 0 if a == b, 1 if a > b (lexicographic).
func compareAddrPort(a, b []byte) int {
	if len(a) != len(b) {
		if len(a) < len(b) {
			return -1
		}
		return 1
	}
	for i := range a {
		if a[i] < b[i] {
			return -1
		}
		if a[i] > b[i] {
			return 1
		}
	}
	return 0
}
