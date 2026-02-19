package fingerprint

import (
	"crypto/md5"
	"encoding/binary"
	"encoding/hex"
)

// SSH_MSG_KEXINIT is the SSH key exchange init message type.
const SSH_MSG_KEXINIT = 20

// Hassh computes the Hassh (client) fingerprint from payload data.
// The payload should start with an SSH-2.0- style banner; we then look for the first
// SSH_MSG_KEXINIT packet and extract kex_algorithms;encryption_algorithms_c2s;mac_algorithms_c2s;compression_algorithms_c2s.
// Returns empty string if the payload does not look like SSH or KEXINIT cannot be parsed.
func Hassh(payload []byte) string {
	if len(payload) < 4 {
		return ""
	}
	// Skip SSH-2.0-* banner line
	offset := 0
	for offset < len(payload) && payload[offset] != '\n' {
		offset++
		if offset >= len(payload) {
			return ""
		}
	}
	offset++ // skip newline
	if offset+5 > len(payload) {
		return ""
	}
	// SSH binary packet: uint32 packet_length (does not include the 4-byte length itself)
	packetLen := binary.BigEndian.Uint32(payload[offset : offset+4])
	offset += 4
	if packetLen < 1 || packetLen > 256*1024 {
		return ""
	}
	if offset+int(packetLen) > len(payload) {
		return ""
	}
	padLen := int(payload[offset])
	offset++
	if padLen < 0 || padLen > int(packetLen)-1 {
		return ""
	}
	payloadEnd := offset + int(packetLen) - 1 - padLen
	if payloadEnd > len(payload) || offset >= payloadEnd {
		return ""
	}
	msgType := payload[offset]
	offset++
	if msgType != SSH_MSG_KEXINIT {
		return ""
	}
	// KEXINIT: 16-byte cookie, then 8 name-lists
	if offset+16 > payloadEnd {
		return ""
	}
	offset += 16 // cookie
	names := make([]string, 0, 8)
	for len(names) < 8 && offset+4 <= payloadEnd {
		nlLen := binary.BigEndian.Uint32(payload[offset : offset+4])
		offset += 4
		if nlLen == 0 {
			names = append(names, "")
			continue
		}
		if offset+int(nlLen) > payloadEnd {
			return ""
		}
		names = append(names, string(payload[offset:offset+int(nlLen)]))
		offset += int(nlLen)
	}
	if len(names) < 8 {
		return ""
	}
	// Hassh = md5(kex;enc_c2s;mac_c2s;comp_c2s) -> indices 0, 2, 4, 6
	hasshInput := names[0] + ";" + names[2] + ";" + names[4] + ";" + names[6]
	sum := md5.Sum([]byte(hasshInput))
	return hex.EncodeToString(sum[:])
}

// IsSSHClientPayload returns true if the payload starts with "SSH-2.0-".
func IsSSHClientPayload(payload []byte) bool {
	return len(payload) >= 7 && string(payload[:7]) == "SSH-2.0"
}
