//go:build linux

package socket

import (
	"errors"
	"net"
	"syscall"
	"testing"
	"unsafe"
)

// cmsg builds one control message the way the kernel lays it out.
func cmsg(level, typ int32, data []byte) []byte {
	b := make([]byte, syscall.CmsgSpace(len(data)))
	h := (*syscall.Cmsghdr)(unsafe.Pointer(&b[0]))
	h.Level = level
	h.Type = typ
	h.SetLen(syscall.CmsgLen(len(data)))
	copy(b[syscall.CmsgLen(0):], data)
	return b
}

func TestOrigDstFromOOB(t *testing.T) {
	v4 := make([]byte, syscall.SizeofSockaddrInet4)
	v4[0] = syscall.AF_INET
	v4[2], v4[3] = 0x00, 0x35 // port 53, network order
	copy(v4[4:8], []byte{192, 0, 2, 1})
	got, err := OrigDstFromOOB(cmsg(syscall.SOL_IP, ipRecvOrigDstAddr, v4))
	if err != nil || !got.IP.Equal(net.ParseIP("192.0.2.1")) || got.Port != 53 {
		t.Fatalf("v4: %v %v", got, err)
	}

	v6 := make([]byte, syscall.SizeofSockaddrInet6)
	v6[0] = syscall.AF_INET6
	v6[2], v6[3] = 0x01, 0xbb // 443
	copy(v6[8:24], net.ParseIP("2001:db8::1"))
	got, err = OrigDstFromOOB(cmsg(syscall.SOL_IPV6, ipv6RecvOrigDst, v6))
	if err != nil || !got.IP.Equal(net.ParseIP("2001:db8::1")) || got.Port != 443 {
		t.Fatalf("v6: %v %v", got, err)
	}

	if _, err := OrigDstFromOOB(nil); !errors.Is(err, ErrNoOrigDst) {
		t.Errorf("empty oob: %v", err)
	}
	if _, err := OrigDstFromOOB(cmsg(syscall.SOL_IP, 8, []byte{1, 2, 3, 4})); !errors.Is(err, ErrNoOrigDst) {
		t.Errorf("unrelated cmsg: %v", err)
	}
	if _, err := OrigDstFromOOB(cmsg(syscall.SOL_IP, ipRecvOrigDstAddr, []byte{1, 2})); err == nil {
		t.Error("short sockaddr accepted")
	}
}

// Binding a transparent socket needs CAP_NET_ADMIN; without it ListenUDP must
// still return a working socket and say transparency did not hold.
func TestListenUDPWithoutPrivilege(t *testing.T) {
	res, err := ListenUDP("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer res.Conn.Close()
	if res.Conn.LocalAddr() == nil {
		t.Fatal("no local address")
	}
	t.Logf("transparent=%v (true only with CAP_NET_ADMIN)", res.Transparent)
}
