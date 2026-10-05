// Package udp captures UDP traffic delivered to the sensor and records it
// without ever replying.
//
// Replying is the one thing a UDP honeypot must not do by default: every
// protocol worth emulating on UDP (DNS, NTP, SNMP, memcached, SSDP) is also an
// amplification vector, and a sensor that answers spoofed requests becomes a
// reflector aimed at whoever the spoofer chose. Capture-only still yields the
// valuable part. A DNS query names what the scanner wanted; a QUIC client's
// first flight contains its entire TLS ClientHello.
//
// UDP source addresses are not authenticated. Records from this package
// describe what was sent, not reliably who sent it, and consumers that build
// address reputation or blocklists must not treat them like TCP records.
package udp

import (
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"spip/internal/dnsinfo"
	"spip/internal/fingerprint"
	"spip/internal/logging"
	"spip/internal/quic"
	"spip/pkg/socket"

	"github.com/google/uuid"
	"golang.org/x/time/rate"
)

// MaxDatagram is the largest datagram read. Anything longer is truncated by
// the kernel and recorded as what arrived.
const MaxDatagram = 65535

// Options configures a Server.
type Options struct {
	Name               string
	CommunityIDSeed    uint16
	IgnoreNets         []netip.Prefix
	CaptureClientHello bool
	RatePerSecond      float64
	Burst              int
}

// Server reads datagrams from one socket and logs them.
type Server struct {
	opt     Options
	logger  logging.Logger
	limiter *rate.Limiter
	asm     *quic.Assembler
	now     func() time.Time

	dropped     atomic.Uint64
	droppedByIP sync.Map // string -> *atomic.Uint64
	limited     atomic.Uint64
	// NoOrigDst counts datagrams that arrived without a TPROXY original
	// destination and were attributed to the listener's own port.
	noOrigDst atomic.Uint64

	stop chan struct{}
	wg   sync.WaitGroup
}

// meta is the per-attempt context carried through QUIC reassembly.
type meta struct {
	src *net.UDPAddr
	dst *socket.OriginalDst
}

func NewServer(logger logging.Logger, opt Options) *Server {
	if opt.RatePerSecond <= 0 {
		opt.RatePerSecond = 200
	}
	if opt.Burst <= 0 {
		opt.Burst = 2000
	}
	return &Server{
		opt:     opt,
		logger:  logger,
		limiter: rate.NewLimiter(rate.Limit(opt.RatePerSecond), opt.Burst),
		asm:     quic.NewAssembler(),
		now:     time.Now,
		stop:    make(chan struct{}),
	}
}

// Serve reads from conn until it is closed. It also runs the timer that
// records QUIC attempts whose ClientHello never completed.
func (s *Server) Serve(conn *net.UDPConn) error {
	s.wg.Add(1)
	go s.sweep()
	defer s.wg.Done()

	local, _ := conn.LocalAddr().(*net.UDPAddr)
	buf := make([]byte, MaxDatagram)
	oob := make([]byte, 512)
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
		dst, err := socket.OrigDstFromOOB(oob[:oobn])
		if err != nil {
			// Delivered to the listen port itself rather than by a TPROXY
			// rule. Record it against that port so the event is not lost.
			s.noOrigDst.Add(1)
			dst = &socket.OriginalDst{IP: net.IPv4zero, Port: 0}
			if local != nil {
				dst = &socket.OriginalDst{IP: local.IP, Port: uint16(local.Port)}
			}
		}
		s.HandleDatagram(append([]byte(nil), buf[:n]...), src, dst)
	}
}

// Shutdown stops the sweeper and records any QUIC attempts still waiting.
func (s *Server) Shutdown() {
	select {
	case <-s.stop:
	default:
		close(s.stop)
	}
	s.wg.Wait()
	for _, at := range s.asm.Flush() {
		s.logAttempt(at)
	}
}

func (s *Server) sweep() {
	defer s.wg.Done()
	t := time.NewTicker(500 * time.Millisecond)
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

// HandleDatagram classifies and records one datagram. Exported for tests.
func (s *Server) HandleDatagram(payload []byte, src *net.UDPAddr, dst *socket.OriginalDst) {
	if src == nil || dst == nil || len(payload) == 0 {
		return
	}
	if s.shouldIgnore(src.IP) {
		s.countDrop(src.IP.String())
		return
	}
	if !s.limiter.Allow() {
		s.limited.Add(1)
		return
	}
	now := s.now()

	if s.handleQUIC(payload, src, dst, now) {
		return
	}
	if info, err := dnsinfo.Parse(payload); err == nil {
		rec := s.base(payload, src, dst, now)
		rec.NetworkProtocol = "dns"
		rec.DNS = info
		rec.Payload = info.Summary()
		s.write(rec)
		return
	}
	rec := s.base(payload, src, dst, now)
	rec.Payload = string(payload)
	s.write(rec)
}

// handleQUIC returns true when the datagram was QUIC and has been dealt with.
func (s *Server) handleQUIC(payload []byte, src *net.UDPAddr, dst *socket.OriginalDst, now time.Time) bool {
	pkts, err := quic.ParseDatagram(payload)
	if errors.Is(err, quic.ErrNotQUIC) || len(pkts) == 0 {
		return false
	}
	first := pkts[0]

	// A version this sensor has no keys for: a version-negotiation probe, a
	// future version, or binary noise whose first byte has the high bit set.
	// Only call it QUIC when it has the shape a client's first datagram must
	// have (RFC 9000 14.1: padded to 1200 bytes; fixed bit set; connection IDs
	// within the v1 limit).
	if first.Frames == nil && !isKnown(first.Version) {
		if len(payload) < 1200 || payload[0]&0x40 == 0 || len(first.DCID) > 20 || len(first.SCID) > 20 || first.Version == 0 {
			return false
		}
		rec := s.base(payload, src, dst, now)
		rec.NetworkProtocol = "quic"
		rec.QUIC = &logging.QUICData{
			Version: quic.VersionName(first.Version), DCID: hex.EncodeToString(first.DCID),
			SCID: hex.EncodeToString(first.SCID), Datagrams: 1,
		}
		rec.Payload = fmt.Sprintf("QUIC version %s probe", quic.VersionName(first.Version))
		s.write(rec)
		return true
	}

	key := src.String() + "|" + hex.EncodeToString(first.DCID)
	added := false
	for i, p := range pkts {
		if p.Frames == nil {
			continue // 0-RTT or Handshake coalesced behind the Initial
		}
		added = true
		if at := s.asm.Add(key, now, p, payload, &meta{src: src, dst: dst}, i == 0); at != nil {
			s.logAttempt(at)
		}
	}
	if added {
		return true
	}
	// Known version but nothing decrypted: a 0-RTT or Handshake packet on its
	// own, or an Initial that failed authentication. Keep it as QUIC so it is
	// not mistaken for DNS or raw noise, marked as not decrypted.
	rec := s.base(payload, src, dst, now)
	rec.NetworkProtocol = "quic"
	rec.QUIC = &logging.QUICData{
		Version: quic.VersionName(first.Version), DCID: hex.EncodeToString(first.DCID),
		SCID: hex.EncodeToString(first.SCID), Datagrams: 1,
	}
	reason := "undecrypted packet"
	if err != nil {
		reason = "Initial did not decrypt"
	}
	rec.Payload = fmt.Sprintf("QUIC v%s %s", quic.VersionName(first.Version), reason)
	s.write(rec)
	return true
}

func isKnown(v uint32) bool {
	return v == quic.Version1 || v == quic.Version2 || v == quic.VersionDraft29
}

// logAttempt writes one record for a QUIC connection attempt, complete or not.
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
	if at.Complete {
		if h, err := quic.ParseHello(at.Hello); err == nil {
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
		} else {
			summary = append(summary, "(ClientHello did not parse)")
		}
	} else {
		summary = append(summary, fmt.Sprintf("(ClientHello incomplete, %d bytes)", at.CryptoBytes))
	}
	rec.Payload = strings.Join(summary, " ")
	s.write(rec)
}

func (s *Server) base(payload []byte, src *net.UDPAddr, dst *socket.OriginalDst, ts time.Time) *logging.ConnectionData {
	srcIP := src.IP.String()
	dstIP := dst.IP.String()
	return &logging.ConnectionData{
		Name:            s.opt.Name,
		Timestamp:       ts.Unix(),
		PayloadHex:      hex.EncodeToString(payload),
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

func (s *Server) shouldIgnore(ip net.IP) bool {
	if len(s.opt.IgnoreNets) == 0 {
		return false
	}
	addr, ok := netip.AddrFromSlice(ip)
	if !ok {
		return false
	}
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

// Report logs what was suppressed since start: dropped sources, rate-limited
// datagrams, QUIC attempts refused for memory, retransmissions folded into
// earlier records, and datagrams that bypassed TPROXY.
func (s *Server) Report() {
	parts := []string{}
	if n := s.dropped.Load(); n > 0 {
		per := []string{}
		s.droppedByIP.Range(func(k, v any) bool {
			per = append(per, fmt.Sprintf("%s=%d", k, v.(*atomic.Uint64).Load()))
			return true
		})
		sort.Strings(per)
		parts = append(parts, fmt.Sprintf("ignore_sources dropped %d (%s)", n, strings.Join(per, " ")))
	}
	if n := s.limited.Load(); n > 0 {
		parts = append(parts, fmt.Sprintf("rate limited %d", n))
	}
	overflow, retrans := s.asm.Stats()
	if n := overflow; n > 0 {
		parts = append(parts, fmt.Sprintf("quic attempts refused at capacity %d", n))
	}
	if n := retrans; n > 0 {
		parts = append(parts, fmt.Sprintf("quic retransmits folded %d", n))
	}
	if n := s.noOrigDst.Load(); n > 0 {
		parts = append(parts, fmt.Sprintf("datagrams without TPROXY original destination %d", n))
	}
	if len(parts) == 0 {
		return
	}
	s.logger.Info("udp", "since start: "+strings.Join(parts, "; "))
}
