package quic

import (
	"sort"
	"sync"
	"time"
)

// Bounds on what unauthenticated senders can make the sensor hold: at most
// MaxPending attempts of MaxCryptoBytes each. A ClientHello is a few hundred
// bytes, about 2 KB with post-quantum key shares.
const (
	MaxPending      = 1024
	MaxCryptoBytes  = 8 * 1024
	PendingTTL      = 3 * time.Second
	CompletedTTL    = 30 * time.Second
	MaxRawKeepBytes = 1500
	maxSegments     = 64
)

// Attempt is one client connection attempt: every Initial datagram sharing a
// source address and Destination Connection ID. Retransmissions fold into it.
type Attempt struct {
	Key       string
	Meta      any
	FirstSeen time.Time
	Version   uint32
	DCID      []byte
	SCID      []byte
	TokenLen  int
	Datagrams int
	Bytes     int
	Raw       []byte

	// Hello is the complete ClientHello handshake message once it has arrived.
	Hello       []byte
	Complete    bool
	CryptoBytes int
	Pings       int
	CloseReason string

	segments map[uint64][]byte
	stored   int
}

// Assembler gathers CRYPTO frames per attempt until the ClientHello is whole.
// It is safe for concurrent use.
type Assembler struct {
	mu          sync.Mutex
	pending     map[string]*Attempt
	completed   map[string]time.Time
	overflow    uint64
	retransmits uint64
}

func NewAssembler() *Assembler {
	return &Assembler{pending: map[string]*Attempt{}, completed: map[string]time.Time{}}
}

// Add folds one decrypted Initial packet into its attempt and returns the
// attempt when this packet completed the ClientHello. firstInDatagram must be
// true for the first packet of each datagram so coalesced packets count once.
func (a *Assembler) Add(key string, now time.Time, p *Packet, raw []byte, meta any, firstInDatagram bool) *Attempt {
	a.mu.Lock()
	defer a.mu.Unlock()

	if _, done := a.completed[key]; done {
		if firstInDatagram {
			a.retransmits++
		}
		return nil
	}
	at, ok := a.pending[key]
	if !ok {
		if len(a.pending)+len(a.completed) >= MaxPending*8 || len(a.pending) >= MaxPending {
			a.overflow++
			return nil
		}
		at = &Attempt{
			Key: key, Meta: meta, FirstSeen: now,
			Version: p.Version, DCID: p.DCID, SCID: p.SCID, TokenLen: p.TokenLen,
			Raw:      append([]byte(nil), raw[:min(len(raw), MaxRawKeepBytes)]...),
			segments: map[uint64][]byte{},
		}
		a.pending[key] = at
	}
	if firstInDatagram {
		at.Datagrams++
		at.Bytes += len(raw)
	}
	if p.Frames != nil {
		at.Pings += p.Frames.Pings
		if p.Frames.Close && at.CloseReason == "" {
			at.CloseReason = p.Frames.CloseReason
		}
		for _, s := range p.Frames.Crypto {
			if len(s.Data) == 0 || s.Offset >= MaxCryptoBytes || len(at.segments) >= maxSegments {
				continue
			}
			if _, dup := at.segments[s.Offset]; dup || at.stored+len(s.Data) > MaxCryptoBytes {
				continue
			}
			at.segments[s.Offset] = s.Data
			at.stored += len(s.Data)
		}
	}
	if hello := at.hello(); hello != nil {
		at.Hello, at.Complete, at.segments = hello, true, nil
		delete(a.pending, key)
		a.completed[key] = now
		return at
	}
	return nil
}

// hello returns the ClientHello once the stream from offset 0 holds all of it.
func (at *Attempt) hello() []byte {
	stream := at.contiguous()
	at.CryptoBytes = len(stream)
	if len(stream) < 4 || stream[0] != 0x01 {
		return nil
	}
	n := int(stream[1])<<16 | int(stream[2])<<8 | int(stream[3])
	if 4+n > MaxCryptoBytes || len(stream) < 4+n {
		return nil
	}
	return append([]byte(nil), stream[:4+n]...)
}

// contiguous joins segments from offset 0 up to the first gap. Segments may
// overlap when a retransmission reframes the stream.
func (at *Attempt) contiguous() []byte {
	offs := make([]uint64, 0, len(at.segments))
	for o := range at.segments {
		offs = append(offs, o)
	}
	sort.Slice(offs, func(i, j int) bool { return offs[i] < offs[j] })
	var out []byte
	for _, o := range offs {
		have := uint64(len(out))
		if o > have {
			break
		}
		d := at.segments[o]
		if o+uint64(len(d)) > have {
			out = append(out, d[have-o:]...)
		}
	}
	return out
}

// Expire returns attempts still incomplete after PendingTTL, so a client whose
// hello never completes is still recorded, and forgets completed attempts
// after CompletedTTL.
func (a *Assembler) Expire(now time.Time) []*Attempt {
	a.mu.Lock()
	defer a.mu.Unlock()
	var out []*Attempt
	for k, at := range a.pending {
		if now.Sub(at.FirstSeen) >= PendingTTL {
			at.CryptoBytes = len(at.contiguous())
			at.segments = nil
			delete(a.pending, k)
			a.completed[k] = now
			out = append(out, at)
		}
	}
	for k, t := range a.completed {
		if now.Sub(t) >= CompletedTTL {
			delete(a.completed, k)
		}
	}
	return out
}

// Flush returns every pending attempt regardless of age.
func (a *Assembler) Flush() []*Attempt {
	return a.Expire(time.Now().Add(PendingTTL + CompletedTTL))
}

// Stats returns attempts refused at capacity and retransmissions folded.
func (a *Assembler) Stats() (overflow, retransmits uint64) {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.overflow, a.retransmits
}

// Pending reports how many attempts are waiting for more data.
func (a *Assembler) Pending() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return len(a.pending)
}
