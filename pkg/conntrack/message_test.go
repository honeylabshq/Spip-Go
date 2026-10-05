package conntrack

import (
	"encoding/binary"
	"errors"
	"net/netip"
	"testing"
)

func tupleAttr(typ uint16, src, dst netip.AddrPort) []byte {
	st, dt := uint16(ctaIPv4Src), uint16(ctaIPv4Dst)
	if !src.Addr().Is4() {
		st, dt = ctaIPv6Src, ctaIPv6Dst
	}
	ip := append(attr(st, src.Addr().AsSlice()), attr(dt, dst.Addr().AsSlice())...)
	l4 := append(attr(ctaProtoNum, []byte{17}), attr(ctaProtoSrc, be16(src.Port()))...)
	l4 = append(l4, attr(ctaProtoDst, be16(dst.Port()))...)
	return attr(typ|nlaFNested, append(attr(ctaTupleIP|nlaFNested, ip), attr(ctaTupleProto|nlaFNested, l4)...))
}

func message(typ uint16, seq uint32, body []byte) []byte {
	m := make([]byte, nlmsgHdrLen)
	binary.NativeEndian.PutUint32(m[0:4], uint32(nlmsgHdrLen+len(body)))
	binary.NativeEndian.PutUint16(m[4:6], typ)
	binary.NativeEndian.PutUint32(m[8:12], seq)
	return append(m, body...)
}

// A REDIRECTed probe to 53: the entry's original tuple keeps port 53, its
// reply tuple runs from the listener on 8080 back to the sender.
func ctReply(seq uint32, sender, orig, listener netip.AddrPort) []byte {
	body := append([]byte{afInet, 0, 0, 0}, tupleAttr(ctaTupleOrig, sender, orig)...)
	body = append(body, tupleAttr(ctaTupleReply, listener, sender)...)
	body = append(body, attr(3, []byte{0, 0, 0, 0x8})...) // CTA_STATUS, ignored
	return message(subsysCT<<8|msgCTNew, seq, body)
}

func TestRequestCarriesTheReplyTuple(t *testing.T) {
	sender := netip.MustParseAddrPort("198.51.100.7:40000")
	listener := netip.MustParseAddrPort("192.0.2.1:8080")
	req, err := getRequest(9, 17, sender, listener)
	if err != nil {
		t.Fatal(err)
	}
	if got := binary.NativeEndian.Uint16(req[4:6]); got != subsysCT<<8|msgCTGet {
		t.Fatalf("message type %#x", got)
	}
	if int(binary.NativeEndian.Uint32(req[0:4])) != len(req) {
		t.Fatal("length field does not match the message")
	}
	var reply []byte
	attrs(req[nlmsgHdrLen+4:], func(typ uint16, val []byte) error {
		if typ == ctaTupleReply {
			reply = val
		}
		return nil
	})
	want := tupleAttr(ctaTupleReply, listener, sender)
	if string(reply) != string(want[4:]) {
		t.Fatalf("reply tuple\n got %x\nwant %x", reply, want[4:])
	}
}

func TestParseReturnsTheOriginalDestination(t *testing.T) {
	sender := netip.MustParseAddrPort("198.51.100.7:40000")
	orig := netip.MustParseAddrPort("192.0.2.1:53")
	listener := netip.MustParseAddrPort("192.0.2.1:8080")
	b := append(message(subsysCT<<8|msgCTNew, 4, []byte{afInet, 0, 0, 0}), ctReply(5, sender, orig, listener)...)
	dst, done, err := parseReply(b, 5)
	if err != nil || !done || dst != orig {
		t.Fatalf("got %v %v %v, want %v", dst, done, err, orig)
	}
}

func TestParseIPv6(t *testing.T) {
	sender := netip.MustParseAddrPort("[2001:db8::7]:40000")
	orig := netip.MustParseAddrPort("[2001:db8::1]:443")
	body := append([]byte{afInet6, 0, 0, 0}, tupleAttr(ctaTupleOrig, sender, orig)...)
	dst, _, err := parseReply(message(subsysCT<<8|msgCTNew, 1, body), 1)
	if err != nil || dst != orig {
		t.Fatalf("got %v %v", dst, err)
	}
}

func TestMissingEntry(t *testing.T) {
	errno := make([]byte, 4)
	binary.NativeEndian.PutUint32(errno, uint32(0xfffffffe)) // -ENOENT
	_, done, err := parseReply(message(nlmsgError, 3, errno), 3)
	if !done || !errors.Is(err, ErrNotFound) {
		t.Fatalf("got %v %v", done, err)
	}
}

func TestForeignSequenceIsSkipped(t *testing.T) {
	_, done, err := parseReply(message(nlmsgDone, 8, nil), 9)
	if done || err != nil {
		t.Fatalf("got %v %v", done, err)
	}
}

func TestMalformedInputIsAnError(t *testing.T) {
	for _, b := range [][]byte{
		{0xff, 0xff, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
		message(subsysCT<<8|msgCTNew, 1, []byte{2, 0}),
		message(subsysCT<<8|msgCTNew, 1, append([]byte{2, 0, 0, 0}, 0xff, 0x00, 0x01, 0x80)),
	} {
		if _, _, err := parseReply(b, 1); err == nil {
			t.Errorf("%x parsed without error", b)
		}
	}
}

func TestFamilyMismatch(t *testing.T) {
	if _, err := getRequest(1, 17, netip.MustParseAddrPort("[2001:db8::7]:1"), netip.MustParseAddrPort("192.0.2.1:2")); err == nil {
		t.Fatal("mixed families accepted")
	}
}

func FuzzParseReply(f *testing.F) {
	f.Add(ctReply(1, netip.MustParseAddrPort("198.51.100.7:40000"),
		netip.MustParseAddrPort("192.0.2.1:53"), netip.MustParseAddrPort("192.0.2.1:8080")))
	f.Fuzz(func(t *testing.T, b []byte) {
		parseReply(b, 1)
	})
}
