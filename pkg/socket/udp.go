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

// UDP capture uses TPROXY. Under the nat REDIRECT the TCP side uses, the
// kernel rewrites the destination before the socket sees it and UDP has no
// SO_ORIGINAL_DST, so IP_RECVORIGDSTADDR would report the listener's own port.
const (
	ipTransparent     = 19 // IP_TRANSPARENT
	ipRecvOrigDstAddr = 20 // IP_RECVORIGDSTADDR
	ipv6RecvOrigDst   = 74 // IPV6_RECVORIGDSTADDR
	ipv6Transparent   = 75 // IPV6_TRANSPARENT
	soRxqOvfl         = 40 // SO_RXQ_OVFL

	udpReceiveBuffer = 4 << 20
)

// ErrNoOrigDst means the datagram was not delivered by a TPROXY rule.
var ErrNoOrigDst = errors.New("no original destination control message")

// UDPListener is a UDP socket prepared for TPROXY capture.
type UDPListener struct {
	Conn *net.UDPConn
	// Transparent is false when IP_TRANSPARENT was refused (no CAP_NET_ADMIN);
	// TPROXY rules cannot deliver to such a socket.
	Transparent bool
}

// ListenUDP opens a UDP listener that reports each datagram's original
// destination and kernel drop count. network is "udp", "udp4" or "udp6".
func ListenUDP(network, addr string) (*UDPListener, error) {
	l := &UDPListener{}
	lc := net.ListenConfig{
		Control: func(netw, _ string, c syscall.RawConn) error {
			var setErr error
			err := c.Control(func(fd uintptr) {
				s := int(fd)
				v6 := netw == "udp6"
				if v6 {
					l.Transparent = syscall.SetsockoptInt(s, syscall.SOL_IPV6, ipv6Transparent, 1) == nil
				} else {
					l.Transparent = syscall.SetsockoptInt(s, syscall.SOL_IP, ipTransparent, 1) == nil
				}
				// A dual-stack socket also receives IPv4, which reports its
				// destination through the IPv4 option.
				v4err := syscall.SetsockoptInt(s, syscall.SOL_IP, ipRecvOrigDstAddr, 1)
				if !v6 && v4err != nil {
					setErr = fmt.Errorf("setsockopt IP_RECVORIGDSTADDR: %w", v4err)
					return
				}
				if v6 {
					if err := syscall.SetsockoptInt(s, syscall.SOL_IPV6, ipv6RecvOrigDst, 1); err != nil {
						setErr = fmt.Errorf("setsockopt IPV6_RECVORIGDSTADDR: %w", err)
						return
					}
				}
				_ = syscall.SetsockoptInt(s, syscall.SOL_SOCKET, soRxqOvfl, 1)
				_ = syscall.SetsockoptInt(s, syscall.SOL_SOCKET, syscall.SO_RCVBUF, udpReceiveBuffer)
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
	l.Conn = conn
	return l, nil
}

// Control is what one datagram's control messages carried.
type Control struct {
	OrigDst *OriginalDst
	// Drops is the kernel's cumulative count of datagrams dropped on this
	// socket for lack of buffer space; HasDrops reports whether it was sent.
	Drops    uint32
	HasDrops bool
}

// ParseControl reads the control messages returned by ReadMsgUDP. It returns
// ErrNoOrigDst, with any drop count still set, when no original destination
// was present.
func ParseControl(oob []byte) (*Control, error) {
	c := &Control{}
	if len(oob) == 0 {
		return c, ErrNoOrigDst
	}
	msgs, err := syscall.ParseSocketControlMessage(oob)
	if err != nil {
		return c, fmt.Errorf("parse control messages: %w", err)
	}
	for _, m := range msgs {
		switch {
		case m.Header.Level == syscall.SOL_SOCKET && m.Header.Type == soRxqOvfl && len(m.Data) >= 4:
			c.Drops, c.HasDrops = binary.NativeEndian.Uint32(m.Data), true
		case m.Header.Level == syscall.SOL_IP && m.Header.Type == ipRecvOrigDstAddr:
			if len(m.Data) < syscall.SizeofSockaddrInet4 {
				return c, errors.New("short IPv4 original destination")
			}
			a := (*syscall.RawSockaddrInet4)(unsafe.Pointer(&m.Data[0]))
			p := (*[2]byte)(unsafe.Pointer(&a.Port))
			c.OrigDst = &OriginalDst{IP: append(net.IP(nil), a.Addr[:]...), Port: binary.BigEndian.Uint16(p[:])}
		case m.Header.Level == syscall.SOL_IPV6 && m.Header.Type == ipv6RecvOrigDst:
			if len(m.Data) < syscall.SizeofSockaddrInet6 {
				return c, errors.New("short IPv6 original destination")
			}
			a := (*syscall.RawSockaddrInet6)(unsafe.Pointer(&m.Data[0]))
			p := (*[2]byte)(unsafe.Pointer(&a.Port))
			c.OrigDst = &OriginalDst{IP: append(net.IP(nil), a.Addr[:]...), Port: binary.BigEndian.Uint16(p[:])}
		}
	}
	if c.OrigDst == nil {
		return c, ErrNoOrigDst
	}
	return c, nil
}
