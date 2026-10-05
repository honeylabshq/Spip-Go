package quic

import (
	"errors"
	"fmt"

	"spip/internal/sanitize"
)

// Segment is one CRYPTO frame: a slice of the TLS handshake stream at Offset.
type Segment struct {
	Offset uint64
	Data   []byte
}

// Frames summarises a decrypted Initial payload.
type Frames struct {
	Crypto      []Segment
	Pings       int
	Close       bool
	CloseReason string
}

const (
	maxAckRanges   = 256
	maxCloseReason = 256
)

// parseFrames reads the frame types RFC 9000 allows in an Initial packet.
// Order is not assumed: clients may scatter CRYPTO frames between PADDING and
// PING, and reassembly is by offset.
func parseFrames(b []byte) (*Frames, error) {
	f := &Frames{}
	for len(b) > 0 {
		switch t := b[0]; t {
		case 0x00:
			b = b[1:]
		case 0x01:
			b = b[1:]
			f.Pings++
		case 0x02, 0x03:
			n, err := skipAck(b[1:], t == 0x03)
			if err != nil {
				return f, err
			}
			b = b[1+n:]
		case 0x06:
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
				return f, errors.New("CRYPTO frame beyond packet")
			}
			end := start + int(ln)
			f.Crypto = append(f.Crypto, Segment{Offset: off, Data: append([]byte(nil), b[start:end]...)})
			b = b[end:]
		case 0x1c, 0x1d:
			n, reason, err := readClose(b[1:], t == 0x1c)
			if err != nil {
				return f, err
			}
			f.Close, f.CloseReason = true, reason
			b = b[1+n:]
		default:
			return f, fmt.Errorf("frame type 0x%02x not allowed in an Initial", t)
		}
	}
	return f, nil
}

type varintReader struct {
	b   []byte
	off int
}

func (r *varintReader) next() (uint64, error) {
	v, n, err := readVarint(r.b[r.off:])
	r.off += n
	return v, err
}

func skipAck(b []byte, ecn bool) (int, error) {
	r := &varintReader{b: b}
	for i := 0; i < 2; i++ { // largest acknowledged, ack delay
		if _, err := r.next(); err != nil {
			return 0, err
		}
	}
	count, err := r.next()
	if err != nil {
		return 0, err
	}
	if count > maxAckRanges {
		return 0, fmt.Errorf("implausible ACK range count %d", count)
	}
	fields := 1 + 2*int(count) // first range, then gap and length pairs
	if ecn {
		fields += 3
	}
	for i := 0; i < fields; i++ {
		if _, err := r.next(); err != nil {
			return 0, err
		}
	}
	return r.off, nil
}

func readClose(b []byte, transport bool) (int, string, error) {
	r := &varintReader{b: b}
	if _, err := r.next(); err != nil { // error code
		return 0, "", err
	}
	if transport {
		if _, err := r.next(); err != nil { // offending frame type
			return 0, "", err
		}
	}
	ln, err := r.next()
	if err != nil {
		return 0, "", err
	}
	if ln > uint64(len(b)-r.off) {
		return 0, "", errors.New("CONNECTION_CLOSE reason beyond packet")
	}
	reason := b[r.off : r.off+int(ln)]
	return r.off + int(ln), sanitize.Printable(reason, maxCloseReason), nil
}
