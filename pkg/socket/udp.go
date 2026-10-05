//go:build linux

package socket

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"syscall"
	"unsafe"
)

// UDP capture relies on TPROXY, not on the nat REDIRECT the TCP side uses.
//
// With REDIRECT the kernel rewrites the destination before the socket sees the
// datagram, and UDP has no SO_ORIGINAL_DST. IP_RECVORIGDSTADDR then reports the
// rewritten address: measured on 2026-10-05, a datagram sent to port 53 under
// "REDIRECT --to-ports 7999" arrives with an original destination of :7999, so
// every UDP event would carry the sensor's own listen port. TPROXY delivers the
// datagram unmodified to a socket that has IP_TRANSPARENT set, and the control
// message then carries the port the sender chose.
const (
	ipTransparent     = 19 // IP_TRANSPARENT
	ipRecvOrigDstAddr = 20 // IP_RECVORIGDSTADDR, cmsg type IP_ORIGDSTADDR
	ipv6Transparent   = 75 // IPV6_TRANSPARENT
	ipv6RecvOrigDst   = 74 // IPV6_RECVORIGDSTADDR, cmsg type IPV6_ORIGDSTADDR
)

// ErrNoOrigDst means the datagram carried no original-destination control
// message, which is what happens when no TPROXY rule delivered it (for example
// a datagram sent straight to the listen port).
var ErrNoOrigDst = errors.New("no original destination control message")

// UDPListenResult reports what ListenUDP managed to enable. Transparent is false
// when IP_TRANSPARENT was refused (no CAP_NET_ADMIN): the listener still works
// for datagrams addressed to its own port, but TPROXY cannot deliver to it.
type UDPListenResult struct {
	Conn        *net.UDPConn
	Transparent bool
}

// ListenUDP opens a UDP listener that asks the kernel for the original
// destination of every datagram, and tries to make it transparent so TPROXY
// rules can hand it traffic for any port. network is "udp", "udp4" or "udp6".
func ListenUDP(network, addr string) (*UDPListenResult, error) {
	res := &UDPListenResult{}
	lc := net.ListenConfig{
		Control: func(netw, _ string, c syscall.RawConn) error {
			var setErr error
			err := c.Control(func(fd uintptr) {
				v6 := netw == "udp6"
				// Transparent is best effort; the result says whether it held.
				if v6 {
					res.Transparent = syscall.SetsockoptInt(int(fd), syscall.SOL_IPV6, ipv6Transparent, 1) == nil
				} else {
					res.Transparent = syscall.SetsockoptInt(int(fd), syscall.SOL_IP, ipTransparent, 1) == nil
					// A dual-stack udp socket also receives v4-mapped traffic,
					// so ask for both families where the kernel allows it.
					if netw == "udp" {
						_ = syscall.SetsockoptInt(int(fd), syscall.SOL_IPV6, ipv6Transparent, 1)
					}
				}
				if err := syscall.SetsockoptInt(int(fd), syscall.SOL_IP, ipRecvOrigDstAddr, 1); err != nil && !v6 {
					setErr = fmt.Errorf("setsockopt IP_RECVORIGDSTADDR: %w", err)
				}
				if v6 || netw == "udp" {
					if err := syscall.SetsockoptInt(int(fd), syscall.SOL_IPV6, ipv6RecvOrigDst, 1); err != nil && v6 {
						setErr = fmt.Errorf("setsockopt IPV6_RECVORIGDSTADDR: %w", err)
					}
				}
			})
			if err != nil {
				return err
			}
			return setErr
		},
	}
	pc, err := lc.ListenPacket(context.Background(), network, addr)
	if err != nil {
		return nil, err
	}
	conn, ok := pc.(*net.UDPConn)
	if !ok {
		pc.Close()
		return nil, fmt.Errorf("unexpected packet conn type %T", pc)
	}
	res.Conn = conn
	return res, nil
}

// OrigDstFromOOB returns the destination the sender addressed, read from the
// control messages ReadMsgUDP returned.
func OrigDstFromOOB(oob []byte) (*OriginalDst, error) {
	if len(oob) == 0 {
		return nil, ErrNoOrigDst
	}
	msgs, err := syscall.ParseSocketControlMessage(oob)
	if err != nil {
		return nil, fmt.Errorf("parse control messages: %w", err)
	}
	for _, m := range msgs {
		switch {
		case m.Header.Level == syscall.SOL_IP && m.Header.Type == ipRecvOrigDstAddr:
			if len(m.Data) < syscall.SizeofSockaddrInet4 {
				return nil, fmt.Errorf("short IPv4 original destination")
			}
			a := (*syscall.RawSockaddrInet4)(unsafe.Pointer(&m.Data[0]))
			p := (*[2]byte)(unsafe.Pointer(&a.Port))
			ip := make(net.IP, 4)
			copy(ip, a.Addr[:])
			return &OriginalDst{IP: ip, Port: binary.BigEndian.Uint16(p[:])}, nil
		case m.Header.Level == syscall.SOL_IPV6 && m.Header.Type == ipv6RecvOrigDst:
			if len(m.Data) < syscall.SizeofSockaddrInet6 {
				return nil, fmt.Errorf("short IPv6 original destination")
			}
			a := (*syscall.RawSockaddrInet6)(unsafe.Pointer(&m.Data[0]))
			p := (*[2]byte)(unsafe.Pointer(&a.Port))
			ip := make(net.IP, 16)
			copy(ip, a.Addr[:])
			return &OriginalDst{IP: ip, Port: binary.BigEndian.Uint16(p[:])}, nil
		}
	}
	return nil, ErrNoOrigDst
}
