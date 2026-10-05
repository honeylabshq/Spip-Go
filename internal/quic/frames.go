package quic

import "fmt"

// Segment is one CRYPTO frame: a slice of the TLS handshake stream at Offset.
type Segment struct {
	Offset uint64
	Data   []byte
}

// Frames summarises a decrypted Initial payload.
type Frames struct {
	Crypto  []Segment
	Padding int  // PADDING bytes
	Pings   int  // PING frames
	Acks    int  // ACK frames (a client's first flight normally has none)
	Close   bool // CONNECTION_CLOSE present
	// CloseReason is the reason phrase of a CONNECTION_CLOSE, bounded.
	CloseReason string
}

// parseFrames reads the frame types allowed in an Initial packet (RFC 9000
// table 3): PADDING, PING, ACK, CRYPTO and CONNECTION_CLOSE. Any other type is
// a protocol violation in an Initial and stops the parse with an error, which
// the caller records rather than guessing at the rest.
//
// Chrome splits its ClientHello into many CRYPTO frames, sends them out of
// order and scatters PADDING and PING between them, so nothing here assumes
// order; reassembly is by offset in Assembler.
func parseFrames(b []byte) (*Frames, error) {
	f := &Frames{}
	for len(b) > 0 {
		t := b[0]
		switch {
		case t == 0x00:
			b = b[1:]
			f.Padding++
		case t == 0x01:
			b = b[1:]
			f.Pings++
		case t == 0x02 || t == 0x03:
			n, err := skipAck(b[1:], t == 0x03)
			if err != nil {
				return f, err
			}
			b = b[1+n:]
			f.Acks++
		case t == 0x06:
			off, n1, err := readVarint(b[1:])
			if err != nil {
				return f, err
			}
			ln, n2, err := readVarint(b[1+n1:])
			if err != nil {
				return f, err
			}
			start := 1 + n1 + n2
			if ln > uint64(len(b)-start) {
				return f, fmt.Errorf("CRYPTO frame beyond packet")
			}
			f.Crypto = append(f.Crypto, Segment{Offset: off, Data: append([]byte(nil), b[start:start+int(ln)]...)})
			b = b[start+int(ln):]
		case t == 0x1c || t == 0x1d:
			n, reason, err := readClose(b[1:], t == 0x1c)
			if err != nil {
				return f, err
			}
			f.Close = true
			f.CloseReason = reason
			b = b[1+n:]
		default:
			return f, fmt.Errorf("frame type 0x%02x not allowed in an Initial", t)
		}
	}
	return f, nil
}

func skipAck(b []byte, ecn bool) (int, error) {
	off := 0
	read := func() (uint64, error) {
		v, n, err := readVarint(b[off:])
		off += n
		return v, err
	}
	if _, err := read(); err != nil { // largest acknowledged
		return 0, err
	}
	if _, err := read(); err != nil { // ack delay
		return 0, err
	}
	count, err := read()
	if err != nil {
		return 0, err
	}
	if _, err := read(); err != nil { // first range
		return 0, err
	}
	if count > 256 {
		return 0, fmt.Errorf("implausible ACK range count %d", count)
	}
	for i := uint64(0); i < count*2; i++ {
		if _, err := read(); err != nil {
			return 0, err
		}
	}
	if ecn {
		for i := 0; i < 3; i++ {
			if _, err := read(); err != nil {
				return 0, err
			}
		}
	}
	return off, nil
}

func readClose(b []byte, transport bool) (int, string, error) {
	off := 0
	if _, n, err := readVarint(b[off:]); err != nil { // error code
		return 0, "", err
	} else {
		off += n
	}
	if transport {
		if _, n, err := readVarint(b[off:]); err != nil { // frame type
			return 0, "", err
		} else {
			off += n
		}
	}
	ln, n, err := readVarint(b[off:])
	if err != nil {
		return 0, "", err
	}
	off += n
	if ln > uint64(len(b)-off) {
		return 0, "", fmt.Errorf("CONNECTION_CLOSE reason beyond packet")
	}
	reason := b[off : off+int(ln)]
	if len(reason) > 256 {
		reason = reason[:256]
	}
	return off + int(ln), string(reason), nil
}
