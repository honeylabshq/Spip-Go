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
	drops := make([]byte, 4)
	drops[0] = 7 // native endian on every supported platform is little endian
	c, err := ParseControl(append(cmsg(syscall.SOL_SOCKET, soRxqOvfl, drops), cmsg(syscall.SOL_IP, ipRecvOrigDstAddr, v4)...))
	if err != nil || !c.OrigDst.IP.Equal(net.ParseIP("192.0.2.1")) || c.OrigDst.Port != 53 || !c.HasDrops || c.Drops != 7 {
		t.Fatalf("v4: %+v %v", c, err)
	}

	v6 := make([]byte, syscall.SizeofSockaddrInet6)
	v6[0] = syscall.AF_INET6
	v6[2], v6[3] = 0x01, 0xbb // 443
	copy(v6[8:24], net.ParseIP("2001:db8::1"))
	c, err = ParseControl(cmsg(syscall.SOL_IPV6, ipv6RecvOrigDst, v6))
	if err != nil || !c.OrigDst.IP.Equal(net.ParseIP("2001:db8::1")) || c.OrigDst.Port != 443 || c.HasDrops {
		t.Fatalf("v6: %+v %v", c, err)
	}

	if _, err := ParseControl(nil); !errors.Is(err, ErrNoOrigDst) {
		t.Errorf("empty oob: %v", err)
	}
	if _, err := ParseControl(cmsg(syscall.SOL_IP, 8, []byte{1, 2, 3, 4})); !errors.Is(err, ErrNoOrigDst) {
		t.Errorf("unrelated cmsg: %v", err)
	}
	if _, err := ParseControl(cmsg(syscall.SOL_IP, ipRecvOrigDstAddr, []byte{1, 2})); err == nil {
		t.Error("short sockaddr accepted")
	}
}

// Without CAP_NET_ADMIN the socket still works and reports Transparent false.
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
