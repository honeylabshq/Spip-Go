package fingerprint

import (
	"encoding/binary"
	"testing"
)

func TestIsSSHClientPayload(t *testing.T) {
	if !IsSSHClientPayload([]byte("SSH-2.0-OpenSSH_8.0")) {
		t.Error("expected true for SSH-2.0- prefix")
	}
	if IsSSHClientPayload([]byte("HTTP/1.1")) {
		t.Error("expected false for non-SSH")
	}
	if IsSSHClientPayload([]byte("SSH-2")) {
		t.Error("expected false for short payload")
	}
}

func TestHassh_NonSSH(t *testing.T) {
	if Hassh([]byte("not ssh")) != "" {
		t.Error("expected empty for non-SSH payload")
	}
}

func TestHassh_ShortPayload(t *testing.T) {
	if Hassh([]byte("SSH-2.0-x\n")) != "" {
		t.Error("expected empty for payload too short for KEXINIT")
	}
}

// buildBannerPlusKEXINIT builds a minimal SSH-2.0 banner plus KEXINIT packet for Hassh tests.
func buildBannerPlusKEXINIT(t *testing.T) []byte {
	t.Helper()
	banner := []byte("SSH-2.0-OpenSSH_8.0\r\n")
	names := []string{
		"curve25519-sha256",
		"ssh-ed25519",
		"chacha20-poly1305@openssh.com",
		"chacha20-poly1305@openssh.com",
		"umac-64-etm@openssh.com",
		"umac-64-etm@openssh.com",
		"none",
		"none",
	}
	var nlPart []byte
	for _, n := range names {
		b := []byte(n)
		var l [4]byte
		binary.BigEndian.PutUint32(l[:], uint32(len(b)))
		nlPart = append(nlPart, l[:]...)
		nlPart = append(nlPart, b...)
	}
	kexinit := make([]byte, 1+16+len(nlPart))
	kexinit[0] = SSH_MSG_KEXINIT
	copy(kexinit[1:17], make([]byte, 16))
	copy(kexinit[17:], nlPart)
	payloadLen := 1 + len(kexinit)
	padLen := 8 - (payloadLen % 8)
	if padLen < 4 {
		padLen += 8
	}
	totalLen := payloadLen + padLen
	packet := make([]byte, 4+1+len(kexinit)+padLen)
	binary.BigEndian.PutUint32(packet[0:4], uint32(totalLen))
	packet[4] = byte(padLen)
	copy(packet[5:], kexinit)
	return append(banner, packet...)
}

func TestHassh_WithBannerAndKEXINITInOnePayload(t *testing.T) {
	payload := buildBannerPlusKEXINIT(t)
	got := Hassh(payload)
	if got == "" {
		t.Fatal("expected Hassh to be set when payload contains banner and KEXINIT in one buffer")
	}
	if len(got) != 32 {
		t.Errorf("expected 32-char hex hassh, got len %d: %q", len(got), got)
	}
	if Hassh(payload) != got {
		t.Error("Hassh must be deterministic for same payload")
	}
}

func TestHassh_BannerOnlyReturnsEmpty(t *testing.T) {
	// Payload with no KEXINIT must return empty Hassh.
	payload := []byte("SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.10\r\n")
	if Hassh(payload) != "" {
		t.Error("expected empty Hassh for banner-only payload (no KEXINIT)")
	}
}
