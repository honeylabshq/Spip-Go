//go:build linux

package socket

import (
	"encoding/binary"
	"fmt"
	"net"
	"syscall"
	"unsafe"
)

// SOL_IP (0) and SO_ORIGINAL_DST (80) are Linux netfilter constants for
// retrieving the pre-NAT destination of a redirected TCP connection.
// SOL_IPV6 (41) + IP6T_SO_ORIGINAL_DST (also 80) are the IPv6 equivalents.
const (
	solIP             = 0
	soOriginalDst     = 80
	solIPv6           = 41
	ip6tSoOriginalDst = 80
)

// OriginalDst represents the original destination of a redirected connection
type OriginalDst struct {
	IP   net.IP
	Port uint16
}

// GetOriginalDst retrieves the original destination of a redirected TCP connection
// using the SO_ORIGINAL_DST socket option (Linux netfilter).
func GetOriginalDst(conn *net.TCPConn) (*OriginalDst, error) {
	rawConn, err := conn.SyscallConn()
	if err != nil {
		return nil, fmt.Errorf("failed to get raw connection: %w", err)
	}

	var addr syscall.RawSockaddrInet4
	addrLen := uint32(syscall.SizeofSockaddrInet4)
	var opErr error

	controlErr := rawConn.Control(func(fd uintptr) {
		_, _, errno := syscall.Syscall6(
			syscall.SYS_GETSOCKOPT,
			fd,
			solIP,
			soOriginalDst,
			uintptr(unsafe.Pointer(&addr)),
			uintptr(unsafe.Pointer(&addrLen)),
			0,
		)
		if errno != 0 {
			opErr = fmt.Errorf("getsockopt SO_ORIGINAL_DST: %w", errno)
		}
	})
	if controlErr != nil {
		return nil, fmt.Errorf("control error: %w", controlErr)
	}
	if opErr != nil {
		return nil, opErr
	}

	// Port is in network byte order in the sockaddr; read raw bytes as big-endian.
	portBytes := (*[2]byte)(unsafe.Pointer(&addr.Port))
	port := binary.BigEndian.Uint16(portBytes[:])

	return &OriginalDst{
		IP:   net.IP(addr.Addr[:]),
		Port: port,
	}, nil
}

// GetOriginalDstV6 is the IPv6 counterpart of GetOriginalDst: it reads the
// pre-NAT destination of a redirected TCP connection via IP6T_SO_ORIGINAL_DST
// (SOL_IPV6). Used for connections accepted over IPv6 once ip6tables REDIRECT
// rules are in place on the sensor.
func GetOriginalDstV6(conn *net.TCPConn) (*OriginalDst, error) {
	rawConn, err := conn.SyscallConn()
	if err != nil {
		return nil, fmt.Errorf("failed to get raw connection: %w", err)
	}

	var addr syscall.RawSockaddrInet6
	addrLen := uint32(syscall.SizeofSockaddrInet6)
	var opErr error

	controlErr := rawConn.Control(func(fd uintptr) {
		_, _, errno := syscall.Syscall6(
			syscall.SYS_GETSOCKOPT,
			fd,
			solIPv6,
			ip6tSoOriginalDst,
			uintptr(unsafe.Pointer(&addr)),
			uintptr(unsafe.Pointer(&addrLen)),
			0,
		)
		if errno != 0 {
			opErr = fmt.Errorf("getsockopt IP6T_SO_ORIGINAL_DST: %w", errno)
		}
	})
	if controlErr != nil {
		return nil, fmt.Errorf("control error: %w", controlErr)
	}
	if opErr != nil {
		return nil, opErr
	}

	portBytes := (*[2]byte)(unsafe.Pointer(&addr.Port))
	port := binary.BigEndian.Uint16(portBytes[:])

	return &OriginalDst{
		IP:   net.IP(addr.Addr[:]),
		Port: port,
	}, nil
}

// GetOriginalDstAuto picks the v4 or v6 retrieval path from the connection's
// address family. The agent's listener is dual-stack (net.Listen("tcp",
// ":port")), so it accepts both families; v4 (and v4-mapped) peers use
// SO_ORIGINAL_DST, real IPv6 peers use IP6T_SO_ORIGINAL_DST. The v4 path is
// unchanged for existing traffic.
func GetOriginalDstAuto(conn *net.TCPConn) (*OriginalDst, error) {
	if ra, ok := conn.RemoteAddr().(*net.TCPAddr); ok && ra.IP.To4() == nil {
		return GetOriginalDstV6(conn)
	}
	return GetOriginalDst(conn)
}
