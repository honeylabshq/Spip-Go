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
	ipOrigDstAddr     = 20
	solIPv6           = 41
	ip6tSoOriginalDst = 80
	ipv6OrigDstAddr   = 74
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

// EnableUDPOriginalDst enables Linux control messages that carry the
// pre-REDIRECT destination address for UDP packets. The returned destination is
// read from ReadMsgUDP oob data by OriginalDstFromControlMessages.
func EnableUDPOriginalDst(conn *net.UDPConn) error {
	rawConn, err := conn.SyscallConn()
	if err != nil {
		return fmt.Errorf("failed to get raw UDP connection: %w", err)
	}

	var opErr error
	controlErr := rawConn.Control(func(fd uintptr) {
		enabled := false
		if err := syscall.SetsockoptInt(int(fd), solIP, ipOrigDstAddr, 1); err != nil {
			opErr = fmt.Errorf("setsockopt IP_RECVORIGDSTADDR: %w", err)
		} else {
			enabled = true
		}
		if err := syscall.SetsockoptInt(int(fd), solIPv6, ipv6OrigDstAddr, 1); err != nil {
			// IPv4-only sockets can reject the IPv6 option. Keep IPv4 UDP usable
			// and let IPv6-only listeners report the failure through tests/e2e.
			if err != syscall.ENOPROTOOPT && err != syscall.EINVAL && opErr == nil {
				opErr = fmt.Errorf("setsockopt IPV6_RECVORIGDSTADDR: %w", err)
			}
		} else {
			enabled = true
		}
		if enabled {
			opErr = nil
		}
	})
	if controlErr != nil {
		return fmt.Errorf("control error: %w", controlErr)
	}
	return opErr
}

// OriginalDstFromControlMessages parses UDP ReadMsgUDP oob data and returns
// the original destination address supplied by Linux netfilter.
func OriginalDstFromControlMessages(oob []byte) (*OriginalDst, error) {
	msgs, err := syscall.ParseSocketControlMessage(oob)
	if err != nil {
		return nil, fmt.Errorf("parse control messages: %w", err)
	}
	for _, msg := range msgs {
		switch {
		case msg.Header.Level == solIP && msg.Header.Type == ipOrigDstAddr:
			if len(msg.Data) < syscall.SizeofSockaddrInet4 {
				return nil, fmt.Errorf("short IPv4 original destination control message")
			}
			addr := (*syscall.RawSockaddrInet4)(unsafe.Pointer(&msg.Data[0]))
			portBytes := (*[2]byte)(unsafe.Pointer(&addr.Port))
			return &OriginalDst{
				IP:   net.IP(addr.Addr[:]),
				Port: binary.BigEndian.Uint16(portBytes[:]),
			}, nil
		case msg.Header.Level == solIPv6 && msg.Header.Type == ipv6OrigDstAddr:
			if len(msg.Data) < syscall.SizeofSockaddrInet6 {
				return nil, fmt.Errorf("short IPv6 original destination control message")
			}
			addr := (*syscall.RawSockaddrInet6)(unsafe.Pointer(&msg.Data[0]))
			portBytes := (*[2]byte)(unsafe.Pointer(&addr.Port))
			return &OriginalDst{
				IP:   net.IP(addr.Addr[:]),
				Port: binary.BigEndian.Uint16(portBytes[:]),
			}, nil
		}
	}
	return nil, fmt.Errorf("original destination control message not found")
}
