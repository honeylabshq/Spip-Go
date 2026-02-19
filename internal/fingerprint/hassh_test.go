package fingerprint

import (
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
