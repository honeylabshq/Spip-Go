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
const (
	solIP         = 0
	soOriginalDst = 80
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
