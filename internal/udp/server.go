// Package udp records UDP traffic delivered to the sensor and never replies:
// answering spoofed UDP turns a sensor into a reflector. Source addresses are
// not authenticated, so records describe what was sent, not reliably who sent it.
package udp

import (
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"runtime/debug"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"spip/internal/dnsinfo"
	"spip/internal/fingerprint"
	"spip/internal/logging"
	"spip/internal/quic"
	"spip/pkg/conntrack"
	"spip/pkg/socket"

	"github.com/google/uuid"
	"golang.org/x/time/rate"
)

const (
	MaxDatagram      = 65535
	MaxStoredPayload = 2048
	minQUICDatagram  = 1200 // RFC 9000 section 14.1

	defaultRate          = 50
	defaultBurst         = 500
	defaultSourceRate    = 5
	defaultSourceBurst   = 20
	maxTrackedSources    = 16384
	sweepInterval        = 500 * time.Millisecond
	controlMessageBuffer = 512
)

// Options configures a Server. Zero values select the defaults.
type Options struct {
	Name               string
	CommunityIDSeed    uint16
	IgnoreNets         []netip.Prefix
	CaptureClientHello bool
	RatePerSecond      float64
	Burst              int
	SourceRate         float64
	SourceBurst        int
	// Conntrack recovers the original destination of datagrams that a nat
	// REDIRECT delivered, on hosts that cannot use TPROXY. Optional.
	Conntrack OriginalDstResolver
}

// OriginalDstResolver looks up where a sender addressed a flow that reached
// local from remote.
type OriginalDstResolver interface {
	OriginalDst(proto uint8, remote, local netip.AddrPort) (netip.AddrPort, error)
}

// Server reads datagrams from one socket and logs them.
type Server struct {
	opt     Options
	logger  logging.Logger
	limiter *rate.Limiter
	sources *sourceLimiter
	asm     *quic.Assembler
	now     func() time.Time

	dropped     atomic.Uint64
	droppedByIP sync.Map // string -> *atomic.Uint64
	limited     atomic.Uint64
	sourceLimit atomic.Uint64
	noOrigDst   atomic.Uint64
	ctResolved  atomic.Uint64
	ctMissing   atomic.Uint64
	ctPaused    atomic.Uint64

	// listenPort is the socket's own port. A datagram addressed to it was
	// delivered by REDIRECT (or genuinely sent to that port) and is resolved
	// through conntrack. Zero disables resolution.
	listenPort   atomic.Int32
	ct           ctBreaker
	kernelDrops  atomic.Uint32
	panics       atomic.Uint64
	lastPanicLog atomic.Int64

	stop     chan struct{}
	stopOnce sync.Once
	wg       sync.WaitGroup
}

type meta struct {
	src *net.UDPAddr
	dst *socket.OriginalDst
}

func NewServer(logger logging.Logger, opt Options) *Server {
	if opt.RatePerSecond <= 0 {
		opt.RatePerSecond = defaultRate
	}
	if opt.Burst <= 0 {
		opt.Burst = defaultBurst
	}
	if opt.SourceRate <= 0 {
		opt.SourceRate = defaultSourceRate
	}
	if opt.SourceBurst <= 0 {
		opt.SourceBurst = defaultSourceBurst
	}
	return &Server{
		opt:     opt,
		logger:  logger,
		limiter: rate.NewLimiter(rate.Limit(opt.RatePerSecond), opt.Burst),
		sources: newSourceLimiter(opt.SourceRate, opt.SourceBurst, maxTrackedSources),
		asm:     quic.NewAssembler(),
		now:     time.Now,
		stop:    make(chan struct{}),
	}
}

// Serve reads from conn until it is closed.
func (s *Server) Serve(conn *net.UDPConn) error {
	s.wg.Add(1)
	go s.sweep()

	local, _ := conn.LocalAddr().(*net.UDPAddr)
	if local != nil {
		s.listenPort.Store(int32(local.Port))
	}
	buf := make([]byte, MaxDatagram)
	oob := make([]byte, controlMessageBuffer)
	for {
		n, oobn, _, src, err := conn.ReadMsgUDP(buf, oob)
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return nil
			}
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				continue
			}
			return err
		}
		if n == 0 || src == nil {
			continue
		}
		ctl, err := socket.ParseControl(oob[:oobn])
		if ctl.HasDrops {
			s.kernelDrops.Store(ctl.Drops)
		}
		dst := ctl.OrigDst
		if err != nil {
			s.noOrigDst.Add(1)
			dst = &socket.OriginalDst{IP: net.IPv4zero, Port: 0}
			if local != nil {
				dst = &socket.OriginalDst{IP: local.IP, Port: uint16(local.Port)}
			}
		}
		s.HandleDatagram(append([]byte(nil), buf[:n]...), src, dst)
	}
}

// redirected returns the destination the sender used for a datagram that
// arrived addressed to the listener itself. Under REDIRECT that is every
// datagram; under TPROXY only a genuine probe to the listener's port, for
// which conntrack returns the same port. On any failure the listener's own
// address is kept, so the datagram is still recorded.
func (s *Server) redirected(src *net.UDPAddr, dst *socket.OriginalDst, now time.Time) *socket.OriginalDst {
	remote, ok1 := netip.AddrFromSlice(src.IP)
	local, ok2 := netip.AddrFromSlice(dst.IP)
	if !ok1 || !ok2 || local.Unmap().IsUnspecified() {
		s.ctMissing.Add(1)
		return dst
	}
	if !s.ct.allow(now) {
		s.ctPaused.Add(1)
		return dst
	}
	orig, err := s.opt.Conntrack.OriginalDst(17,
		netip.AddrPortFrom(remote.Unmap(), uint16(src.Port)), netip.AddrPortFrom(local.Unmap(), dst.Port))
	s.ct.record(now, err)
	if err != nil {
		s.ctMissing.Add(1)
		return dst
	}
	s.ctResolved.Add(1)
	return &socket.OriginalDst{IP: orig.Addr().AsSlice(), Port: orig.Port()}
}

// ctBreaker stops conntrack lookups for a while after consecutive failures
// that are not a plain "no such entry", so a stuck netlink socket costs a
// few timeouts rather than one per datagram.
type ctBreaker struct {
	mu          sync.Mutex
	streak      int
	pausedUntil time.Time
}

const (
	ctFailuresBeforePause = 3
	ctPause               = 30 * time.Second
)

func (b *ctBreaker) allow(now time.Time) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	return !now.Before(b.pausedUntil)
}

func (b *ctBreaker) record(now time.Time, err error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if err == nil || errors.Is(err, conntrack.ErrNotFound) {
		b.streak = 0
		return
	}
	b.streak++
	if b.streak >= ctFailuresBeforePause {
		b.streak = 0
		b.pausedUntil = now.Add(ctPause)
	}
}

// Shutdown stops the sweeper and records QUIC attempts still pending.
func (s *Server) Shutdown() {
	s.stopOnce.Do(func() { close(s.stop) })
	s.wg.Wait()
	for _, at := range s.asm.Flush() {
		s.logAttempt(at)
	}
}

func (s *Server) sweep() {
	defer s.wg.Done()
	t := time.NewTicker(sweepInterval)
	defer t.Stop()
	for {
		select {
		case <-s.stop:
			return
		case <-t.C:
			for _, at := range s.asm.Expire(s.now()) {
				s.logAttempt(at)
			}
		}
	}
}

// HandleDatagram classifies and records one datagram.
func (s *Server) HandleDatagram(payload []byte, src *net.UDPAddr, dst *socket.OriginalDst) {
	if src == nil || dst == nil || len(payload) == 0 {
		return
	}
	defer s.recoverDatagram()

	addr, ok := netip.AddrFromSlice(src.IP)
	if !ok {
		return
	}
	if s.shouldIgnore(addr) {
		s.countDrop(addr.Unmap().String())
		return
	}
	now := s.now()
	if !s.sources.allow(addr, now) {
		s.sourceLimit.Add(1)
		return
	}
	if !s.limiter.AllowN(now, 1) {
		s.limited.Add(1)
		return
	}
	// Resolved only after the drop list and both rate limits, so a flood
	// costs no conntrack round trips beyond what the limits admit.
	if p := s.listenPort.Load(); p != 0 && int32(dst.Port) == p && s.opt.Conntrack != nil {
		dst = s.redirected(src, dst, now)
	}

	if s.handleQUIC(payload, src, dst, now) {
		return
	}
	rec := s.base(payload, src, dst, now)
	if info, err := dnsinfo.Parse(payload); err == nil {
		rec.NetworkProtocol = "dns"
		rec.DNS = info
		rec.Payload = info.Summary()
	} else {
		rec.Payload = string(payload[:min(len(payload), MaxStoredPayload)])
	}
	s.write(rec)
}

func (s *Server) recoverDatagram() {
	r := recover()
	if r == nil {
		return
	}
	s.panics.Add(1)
	now := time.Now().Unix()
	if last := s.lastPanicLog.Load(); now-last >= 60 && s.lastPanicLog.CompareAndSwap(last, now) {
		s.logger.Error("udp", fmt.Sprintf("datagram handler recovered from panic: %v\n%s", r, debug.Stack()))
	}
}

// handleQUIC returns true when the datagram was QUIC and has been handled.
func (s *Server) handleQUIC(payload []byte, src *net.UDPAddr, dst *socket.OriginalDst, now time.Time) bool {
	pkts, err := quic.ParseDatagram(payload)
	if len(pkts) == 0 {
		return false
	}
	first := pkts[0]

	if !quic.Known(first.Version) {
		// Unknown versions count as QUIC only with the shape a client's first
		// datagram must have; anything else is left to the other classifiers.
		if len(payload) < minQUICDatagram || payload[0]&0x40 == 0 || first.Version == 0 ||
			len(first.DCID) > 20 || len(first.SCID) > 20 {
			return false
		}
		s.writeQUICHeader(payload, src, dst, now, first, "probe")
		return true
	}

	key := src.String() + "|" + hex.EncodeToString(first.DCID)
	decrypted := false
	for i, p := range pkts {
		if p.Frames == nil {
			continue
		}
		decrypted = true
		if at := s.asm.Add(key, now, p, payload, &meta{src: src, dst: dst}, i == 0); at != nil {
			s.logAttempt(at)
		}
	}
	if !decrypted {
		reason := "undecrypted packet"
		if err != nil {
			reason = "Initial did not decrypt"
		}
		s.writeQUICHeader(payload, src, dst, now, first, reason)
	}
	return true
}

func (s *Server) writeQUICHeader(payload []byte, src *net.UDPAddr, dst *socket.OriginalDst, now time.Time, p *quic.Packet, what string) {
	rec := s.base(payload, src, dst, now)
	rec.NetworkProtocol = "quic"
	rec.QUIC = &logging.QUICData{
		Version:   quic.VersionName(p.Version),
		DCID:      hex.EncodeToString(p.DCID),
		SCID:      hex.EncodeToString(p.SCID),
		Datagrams: 1,
	}
	if what == "probe" {
		rec.Payload = "QUIC version " + rec.QUIC.Version + " probe"
	} else {
		rec.Payload = "QUIC v" + rec.QUIC.Version + " " + what
	}
	s.write(rec)
}

func (s *Server) logAttempt(at *quic.Attempt) {
	m, ok := at.Meta.(*meta)
	if !ok || m == nil {
		return
	}
	rec := s.base(at.Raw, m.src, m.dst, at.FirstSeen)
	rec.BytesIn = int64(at.Bytes)
	rec.NetworkProtocol = "quic"
	q := &logging.QUICData{
		Version:       quic.VersionName(at.Version),
		DCID:          hex.EncodeToString(at.DCID),
		SCID:          hex.EncodeToString(at.SCID),
		TokenLength:   at.TokenLen,
		Datagrams:     at.Datagrams,
		Decrypted:     true,
		HelloComplete: at.Complete,
		CryptoBytes:   at.CryptoBytes,
		CloseReason:   at.CloseReason,
	}
	rec.QUIC = q
	summary := []string{"QUIC v" + q.Version, "Initial"}
	switch h, err := quic.ParseHello(at.Hello); {
	case !at.Complete:
		summary = append(summary, fmt.Sprintf("(ClientHello incomplete, %d bytes)", at.CryptoBytes))
	case err != nil:
		summary = append(summary, "(ClientHello did not parse)")
	default:
		rec.IsTLS = true
		rec.TLSJA4 = h.JA4
		rec.TLSJA3 = h.JA3
		rec.TLSServerName = h.ServerName
		rec.TLSSupportedProtocols = h.ALPN
		if s.opt.CaptureClientHello {
			rec.TLSClientHelloHex = hex.EncodeToString(h.HelloRecord)
		}
		q.TransportParamsHash = h.TransportParamsHash
		q.TransportParamsStr = h.TransportParamsStr
		q.TransportParamsHex = h.TransportParamsHex
		q.UserAgent = h.UserAgent
		if h.ServerName != "" {
			summary = append(summary, "sni="+h.ServerName)
		}
		if len(h.ALPN) > 0 {
			summary = append(summary, "alpn="+strings.Join(h.ALPN, ","))
		}
	}
	rec.Payload = strings.Join(summary, " ")
	s.write(rec)
}

func (s *Server) base(payload []byte, src *net.UDPAddr, dst *socket.OriginalDst, ts time.Time) *logging.ConnectionData {
	srcIP, dstIP := src.IP.String(), dst.IP.String()
	return &logging.ConnectionData{
		Name:            s.opt.Name,
		Timestamp:       ts.Unix(),
		PayloadHex:      hex.EncodeToString(payload[:min(len(payload), MaxStoredPayload)]),
		SourceIP:        srcIP,
		SourcePort:      uint16(src.Port),
		DestinationIP:   dstIP,
		DestinationPort: dst.Port,
		SessionID:       uuid.New().String(),
		Transport:       "udp",
		CommunityID:     fingerprint.CommunityIDV1(srcIP, dstIP, uint16(src.Port), dst.Port, 17, s.opt.CommunityIDSeed),
		BytesIn:         int64(len(payload)),
		RecordSeq:       1,
	}
}

func (s *Server) write(rec *logging.ConnectionData) {
	if err := s.logger.LogConnection(rec); err != nil {
		s.logger.Error("udp", fmt.Sprintf("failed to log datagram: %v", err))
	}
}

func (s *Server) shouldIgnore(addr netip.Addr) bool {
	addr = addr.Unmap()
	for _, n := range s.opt.IgnoreNets {
		if n.Contains(addr) {
			return true
		}
	}
	return false
}

func (s *Server) countDrop(ip string) {
	s.dropped.Add(1)
	c, ok := s.droppedByIP.Load(ip)
	if !ok {
		c, _ = s.droppedByIP.LoadOrStore(ip, &atomic.Uint64{})
	}
	c.(*atomic.Uint64).Add(1)
}

// Report logs what was suppressed since start.
func (s *Server) Report() {
	var parts []string
	add := func(n uint64, label string) {
		if n > 0 {
			parts = append(parts, fmt.Sprintf("%s %d", label, n))
		}
	}
	if n := s.dropped.Load(); n > 0 {
		var per []string
		s.droppedByIP.Range(func(k, v any) bool {
			per = append(per, fmt.Sprintf("%s=%d", k, v.(*atomic.Uint64).Load()))
			return true
		})
		sort.Strings(per)
		parts = append(parts, fmt.Sprintf("ignore_sources dropped %d (%s)", n, strings.Join(per, " ")))
	}
	overflow, retransmits := s.asm.Stats()
	add(s.limited.Load(), "rate limited")
	add(s.sourceLimit.Load(), "per-source limited")
	add(uint64(s.kernelDrops.Load()), "kernel receive drops")
	add(overflow, "quic attempts refused at capacity")
	add(retransmits, "quic retransmits folded")
	add(s.noOrigDst.Load(), "datagrams without TPROXY destination")
	add(s.ctResolved.Load(), "redirected datagrams resolved through conntrack")
	add(s.ctMissing.Load(), "redirected datagrams conntrack could not resolve")
	add(s.ctPaused.Load(), "redirected datagrams recorded unresolved while conntrack lookups were paused")
	add(s.panics.Load(), "handler panics recovered")
	if len(parts) > 0 {
		s.logger.Info("udp", "since start: "+strings.Join(parts, "; "))
	}
}
