package quic

import (
	"sort"
	"sync"
	"time"
)

// Limits on what unauthenticated senders can make the sensor hold. A real
// ClientHello is a few hundred bytes to about 2 KB with post-quantum key
// shares, spread over one or two datagrams that arrive within milliseconds.
const (
	MaxPending      = 4096             // attempts waiting for the rest of a hello
	MaxCryptoBytes  = 32 * 1024        // CRYPTO bytes kept per attempt
	MaxHelloBytes   = 16 * 1024        // a hello larger than this is not reassembled
	PendingTTL      = 3 * time.Second  // how long to wait for a split hello
	CompletedTTL    = 30 * time.Second // how long a finished attempt absorbs retransmits
	MaxRawKeepBytes = 1500             // first datagram kept as evidence
)

// Attempt is one client connection attempt: every Initial datagram that shares
// a source address and Destination Connection ID. Clients retransmit their
// Initial when nothing answers, so a capture-only sensor sees several copies;
// they are folded into one Attempt and one record.
type Attempt struct {
	Key       string
	Meta      any // caller's context from the first datagram (addresses)
	FirstSeen time.Time
	Version   uint32
	DCID      []byte
	SCID      []byte
	TokenLen  int
	Datagrams int
	Bytes     int    // total size of those datagrams
	Raw       []byte // first datagram, truncated to MaxRawKeepBytes

	// Hello is the complete ClientHello handshake message (type, length and
	// body, no record header) once every byte of it has arrived.
	Hello       []byte
	Complete    bool
	CryptoBytes int // contiguous CRYPTO bytes from offset 0 when not complete
	Pings       int
	CloseReason string

	segments map[uint64][]byte
	stored   int
}

// Assembler gathers CRYPTO frames per attempt until the ClientHello is whole.
// Safe for concurrent use.
type Assembler struct {
	mu        sync.Mutex
	pending   map[string]*Attempt
	completed map[string]time.Time
	// Overflow counts attempts refused because MaxPending was reached.
	Overflow uint64
	// Retransmits counts datagrams absorbed by an attempt already recorded.
	Retransmits uint64
}

func NewAssembler() *Assembler {
	return &Assembler{pending: map[string]*Attempt{}, completed: map[string]time.Time{}}
}

// Add folds one decrypted Initial packet into its attempt. raw is the whole
// datagram it came in. It returns the attempt when this packet completed the
// ClientHello, and nil otherwise. newDatagram should be true for the first
// packet of each datagram so coalesced packets are not double counted.
func (a *Assembler) Add(key string, now time.Time, p *Packet, raw []byte, meta any, newDatagram bool) *Attempt {
	a.mu.Lock()
	defer a.mu.Unlock()

	if _, done := a.completed[key]; done {
		if newDatagram {
			a.Retransmits++
		}
		return nil
	}
	at, ok := a.pending[key]
	if !ok {
		if len(a.pending) >= MaxPending {
			a.Overflow++
			return nil
		}
		at = &Attempt{
			Key: key, Meta: meta, FirstSeen: now,
			Version: p.Version, DCID: p.DCID, SCID: p.SCID, TokenLen: p.TokenLen,
			segments: map[uint64][]byte{},
		}
		keep := raw
		if len(keep) > MaxRawKeepBytes {
			keep = keep[:MaxRawKeepBytes]
		}
		at.Raw = append([]byte(nil), keep...)
		a.pending[key] = at
	}
	if newDatagram {
		at.Datagrams++
		at.Bytes += len(raw)
	}
	if p.Frames != nil {
		at.Pings += p.Frames.Pings
		if p.Frames.Close && at.CloseReason == "" {
			at.CloseReason = p.Frames.CloseReason
		}
		for _, s := range p.Frames.Crypto {
			if _, dup := at.segments[s.Offset]; dup || len(s.Data) == 0 {
				continue
			}
			if at.stored+len(s.Data) > MaxCryptoBytes {
				break
			}
			at.segments[s.Offset] = s.Data
			at.stored += len(s.Data)
		}
	}
	if hello, ok := at.tryHello(); ok {
		at.Hello = hello
		at.Complete = true
		at.segments = nil
		delete(a.pending, key)
		a.completed[key] = now
		return at
	}
	return nil
}

// tryHello returns the ClientHello when the stream from offset 0 holds all of
// it. Segments may overlap (a retransmission can repackage the stream with
// different frame boundaries), so the contiguous prefix is built by offset.
func (at *Attempt) tryHello() ([]byte, bool) {
	stream := at.contiguous()
	at.CryptoBytes = len(stream)
	if len(stream) < 4 || stream[0] != 0x01 {
		return nil, false
	}
	n := int(stream[1])<<16 | int(stream[2])<<8 | int(stream[3])
	if 4+n > MaxHelloBytes || len(stream) < 4+n {
		return nil, false
	}
	return append([]byte(nil), stream[:4+n]...), true
}

func (at *Attempt) contiguous() []byte {
	offs := make([]uint64, 0, len(at.segments))
	for o := range at.segments {
		offs = append(offs, o)
	}
	sort.Slice(offs, func(i, j int) bool { return offs[i] < offs[j] })
	var out []byte
	for _, o := range offs {
		d := at.segments[o]
		end := o + uint64(len(d))
		have := uint64(len(out))
		if o > have {
			break // gap
		}
		if end <= have {
			continue // already covered
		}
		out = append(out, d[have-o:]...)
	}
	return out
}

// Expire returns attempts that never completed within PendingTTL, so a scanner
// that sends a single truncated Initial is still recorded, and forgets
// completed attempts after CompletedTTL.
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

// Flush returns every pending attempt regardless of age. Used at shutdown.
func (a *Assembler) Flush() []*Attempt {
	return a.Expire(time.Now().Add(PendingTTL + time.Hour))
}

// Stats returns the overflow and retransmit counters.
func (a *Assembler) Stats() (overflow, retransmits uint64) {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.Overflow, a.Retransmits
}

// Pending reports how many attempts are waiting for more data.
func (a *Assembler) Pending() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return len(a.pending)
}
