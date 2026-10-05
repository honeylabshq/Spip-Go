// Package conntrack asks the kernel's connection tracking table where a
// datagram was originally addressed.
//
// Under a nat REDIRECT the kernel rewrites a datagram's destination to the
// listener before the socket sees it, and UDP has no SO_ORIGINAL_DST. The
// conntrack entry for the flow still holds the destination the sender used,
// and the reply direction of that entry is exactly what the listener saw:
// listener address and port towards the sender. Looking the entry up by its
// reply tuple returns the original one.
package conntrack

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
)

// Netlink and ctnetlink constants (linux/netlink.h, linux/netfilter/nfnetlink*.h).
const (
	nlmsgHdrLen   = 16
	nlmsgError    = 2
	nlmsgDone     = 3
	nlmFRequest   = 0x1
	nlaFNested    = 0x8000
	nlaTypeMask   = 0x3fff
	subsysCT      = 1
	msgCTNew      = 0
	msgCTGet      = 1
	ctaTupleOrig  = 1
	ctaTupleReply = 2
	ctaTupleIP    = 1
	ctaTupleProto = 2
	ctaIPv4Src    = 1
	ctaIPv4Dst    = 2
	ctaIPv6Src    = 3
	ctaIPv6Dst    = 4
	ctaProtoNum   = 1
	ctaProtoSrc   = 2
	ctaProtoDst   = 3
	afInet        = 2
	afInet6       = 10
)

// ErrNotFound means the kernel holds no entry for the tuple.
var ErrNotFound = errors.New("no conntrack entry")

func attr(typ uint16, payload []byte) []byte {
	b := make([]byte, 4, 4+len(payload)+3)
	binary.NativeEndian.PutUint16(b[0:2], uint16(4+len(payload)))
	binary.NativeEndian.PutUint16(b[2:4], typ)
	b = append(b, payload...)
	for len(b)%4 != 0 {
		b = append(b, 0)
	}
	return b
}

func be16(v uint16) []byte { return binary.BigEndian.AppendUint16(nil, v) }

// getRequest builds an IPCTNL_MSG_CT_GET for the entry whose reply tuple runs
// from local to remote, which is the entry a REDIRECTed datagram created.
func getRequest(seq uint32, proto uint8, remote, local netip.AddrPort) ([]byte, error) {
	if local.Addr().Is4() != remote.Addr().Is4() {
		return nil, fmt.Errorf("address family mismatch: %v and %v", local, remote)
	}
	family, srcType, dstType := byte(afInet), uint16(ctaIPv4Src), uint16(ctaIPv4Dst)
	if !local.Addr().Is4() {
		family, srcType, dstType = afInet6, ctaIPv6Src, ctaIPv6Dst
	}
	ip := append(attr(srcType, local.Addr().AsSlice()), attr(dstType, remote.Addr().AsSlice())...)
	l4 := append(attr(ctaProtoNum, []byte{proto}), attr(ctaProtoSrc, be16(local.Port()))...)
	l4 = append(l4, attr(ctaProtoDst, be16(remote.Port()))...)
	tuple := append(attr(ctaTupleIP|nlaFNested, ip), attr(ctaTupleProto|nlaFNested, l4)...)
	body := append([]byte{family, 0, 0, 0}, attr(ctaTupleReply|nlaFNested, tuple)...)

	msg := make([]byte, nlmsgHdrLen, nlmsgHdrLen+len(body))
	binary.NativeEndian.PutUint32(msg[0:4], uint32(nlmsgHdrLen+len(body)))
	binary.NativeEndian.PutUint16(msg[4:6], subsysCT<<8|msgCTGet)
	binary.NativeEndian.PutUint16(msg[6:8], nlmFRequest)
	binary.NativeEndian.PutUint32(msg[8:12], seq)
	return append(msg, body...), nil
}

// attrs walks one level of netlink attributes.
func attrs(b []byte, fn func(typ uint16, val []byte) error) error {
	for len(b) >= 4 {
		l := int(binary.NativeEndian.Uint16(b[0:2]))
		if l < 4 || l > len(b) {
			return errors.New("malformed netlink attribute")
		}
		if err := fn(binary.NativeEndian.Uint16(b[2:4])&nlaTypeMask, b[4:l]); err != nil {
			return err
		}
		l = (l + 3) &^ 3
		if l > len(b) {
			break
		}
		b = b[l:]
	}
	return nil
}

// parseReply reads the original destination out of a ctnetlink reply. It
// returns done=false for a message that belongs to another request.
func parseReply(b []byte, seq uint32) (dst netip.AddrPort, done bool, err error) {
	for len(b) >= nlmsgHdrLen {
		l := int(binary.NativeEndian.Uint32(b[0:4]))
		if l < nlmsgHdrLen || l > len(b) {
			return dst, true, errors.New("malformed netlink message")
		}
		typ := binary.NativeEndian.Uint16(b[4:6])
		mseq := binary.NativeEndian.Uint32(b[8:12])
		msg := b[nlmsgHdrLen:l]
		if next := (l + 3) &^ 3; next < len(b) {
			b = b[next:]
		} else {
			b = nil
		}
		if mseq != seq {
			continue
		}
		switch {
		case typ == nlmsgError:
			if len(msg) < 4 {
				return dst, true, errors.New("short netlink error")
			}
			errno := -int32(binary.NativeEndian.Uint32(msg[0:4]))
			if errno == 0 {
				continue
			}
			if errno == 2 { // ENOENT
				return dst, true, ErrNotFound
			}
			return dst, true, fmt.Errorf("conntrack: errno %d", errno)
		case typ == nlmsgDone:
			return dst, true, ErrNotFound
		case typ == subsysCT<<8|msgCTNew:
			if len(msg) < 4 {
				return dst, true, errors.New("short ctnetlink message")
			}
			dst, err = origDst(msg[4:])
			return dst, true, err
		}
	}
	return dst, false, nil
}

func origDst(b []byte) (netip.AddrPort, error) {
	var ip netip.Addr
	var port uint16
	var havePort bool
	err := attrs(b, func(typ uint16, val []byte) error {
		if typ != ctaTupleOrig {
			return nil
		}
		return attrs(val, func(typ uint16, val []byte) error {
			switch typ {
			case ctaTupleIP:
				return attrs(val, func(typ uint16, val []byte) error {
					if typ == ctaIPv4Dst || typ == ctaIPv6Dst {
						if a, ok := netip.AddrFromSlice(val); ok {
							ip = a
						}
					}
					return nil
				})
			case ctaTupleProto:
				return attrs(val, func(typ uint16, val []byte) error {
					if typ == ctaProtoDst && len(val) >= 2 {
						port, havePort = binary.BigEndian.Uint16(val), true
					}
					return nil
				})
			}
			return nil
		})
	})
	if err != nil {
		return netip.AddrPort{}, err
	}
	if !ip.IsValid() || !havePort {
		return netip.AddrPort{}, errors.New("conntrack reply without an original destination")
	}
	return netip.AddrPortFrom(ip, port), nil
}
