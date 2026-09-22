package network

import (
	"bytes"
	cryptotls "crypto/tls"
	"encoding/hex"
	"fmt"
	"net"
	"net/netip"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"spip/internal/fingerprint"
	"spip/internal/logging"
	"spip/internal/tls"
	"spip/pkg/socket"

	"github.com/google/uuid"
	"golang.org/x/time/rate"
)

// Handler handles network connections
type Handler struct {
	logger          logging.Logger
	tlsHandler      *tls.TLSHandler
	limiter         *rate.Limiter
	connections     sync.Map
	readTimeout     time.Duration
	writeTimeout    time.Duration
	name            string
	communityIDSeed uint16
	ignoreNets      []netip.Prefix

	// Dropped traffic leaves no event behind, which is the point of it and
	// also the problem with it: a rule that stops matching, or one that
	// matches far more than intended, looks identical to a quiet network.
	// These counters are what makes the drop list auditable.
	dropped     atomic.Uint64
	droppedByIP sync.Map // string -> *atomic.Uint64
}

// SetIgnoredNets installs the drop list. Traffic from these networks is closed
// before it is read, so it is never logged, fingerprinted or shipped.
func (h *Handler) SetIgnoredNets(nets []netip.Prefix) { h.ignoreNets = nets }

// DropStats returns the total dropped connections and the per-source counts
// since start. Callers must not retain the map.
func (h *Handler) DropStats() (uint64, map[string]uint64) {
	per := make(map[string]uint64)
	h.droppedByIP.Range(func(k, v any) bool {
		per[k.(string)] = v.(*atomic.Uint64).Load()
		return true
	})
	return h.dropped.Load(), per
}

// ReportDrops logs what the drop list actually suppressed. Called on a timer
// and once at shutdown, so a silent sensor can still be told apart from a
// sensor whose rules stopped matching.
func (h *Handler) ReportDrops() {
	total, per := h.DropStats()
	if total == 0 {
		if len(h.ignoreNets) > 0 {
			h.logger.Info("network", fmt.Sprintf(
				"ignore_sources: %d rule(s) configured, 0 connections dropped so far",
				len(h.ignoreNets)))
		}
		return
	}
	parts := make([]string, 0, len(per))
	for ip, n := range per {
		parts = append(parts, fmt.Sprintf("%s=%d", ip, n))
	}
	sort.Strings(parts)
	h.logger.Info("network", fmt.Sprintf(
		"ignore_sources: dropped %d connections since start (%s)",
		total, strings.Join(parts, " ")))
}

func (h *Handler) countDrop(ip string) {
	h.dropped.Add(1)
	c, ok := h.droppedByIP.Load(ip)
	if !ok {
		c, _ = h.droppedByIP.LoadOrStore(ip, &atomic.Uint64{})
	}
	c.(*atomic.Uint64).Add(1)
}

func (h *Handler) shouldIgnore(ip net.IP) bool {
	if len(h.ignoreNets) == 0 {
		return false
	}
	addr, ok := netip.AddrFromSlice(ip)
	if !ok {
		return false
	}
	addr = addr.Unmap()
	for _, n := range h.ignoreNets {
		if n.Contains(addr) {
			return true
		}
	}
	return false
}

// NewHandler creates a new network handler.
// communityIDSeed is passed to Community ID v1 hashing (0 = default).
func NewHandler(logger logging.Logger, tlsHandler *tls.TLSHandler, ratePerSec float64, burst int, readTimeout, writeTimeout time.Duration, name string, communityIDSeed uint16) *Handler {
	if ratePerSec <= 0 {
		ratePerSec = 20
	}
	if burst <= 0 {
		burst = 50000
	}
	if readTimeout <= 0 {
		readTimeout = 30 * time.Second
	}
	if writeTimeout <= 0 {
		writeTimeout = 10 * time.Second
	}

	return &Handler{
		logger:          logger,
		tlsHandler:      tlsHandler,
		limiter:         rate.NewLimiter(rate.Limit(ratePerSec), burst),
		readTimeout:     readTimeout,
		writeTimeout:    writeTimeout,
		name:            name,
		communityIDSeed: communityIDSeed,
	}
}

// Shutdown attempts a graceful shutdown, waiting up to timeout for active connections to finish.
// If connections remain after timeout they are force-closed.
func (h *Handler) Shutdown(timeout time.Duration) error {
	start := time.Now()
	for {
		var active int
		h.connections.Range(func(_, v interface{}) bool {
			active++
			return true
		})
		if active == 0 {
			return nil
		}
		if time.Since(start) > timeout {
			// Force close remaining connections
			h.connections.Range(func(_, v interface{}) bool {
				if c, ok := v.(*net.TCPConn); ok {
					c.Close()
				}
				return true
			})
			return fmt.Errorf("shutdown timed out; %d connections force-closed", active)
		}
		time.Sleep(100 * time.Millisecond)
	}
}

// isHTTPRequest checks if the data looks like an HTTP request
func isHTTPRequest(data []byte) bool {
	methods := []string{"GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH"}
	for _, method := range methods {
		if bytes.HasPrefix(data, []byte(method+" ")) {
			return true
		}
	}
	return false
}

// handleHTTPRequest handles an HTTP request and returns an HTTP response
func handleHTTPRequest(data []byte, sourceIP string) []byte {
	return []byte(fmt.Sprintf("HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: %d\r\n\r\n%s", len(sourceIP), sourceIP))
}

// HandleConnection handles an incoming TCP connection
func (h *Handler) HandleConnection(conn *net.TCPConn) {
	conn.SetKeepAlive(true)
	conn.SetKeepAlivePeriod(60 * time.Second)

	if !h.limiter.Allow() {
		h.logger.Error("network", "Connection rejected due to rate limiting")
		conn.Close()
		return
	}

	if ra, ok := conn.RemoteAddr().(*net.TCPAddr); ok && h.shouldIgnore(ra.IP) {
		// Configured drop. Nothing is read, so nothing is logged, fingerprinted
		// or shipped: this is the difference between hiding traffic from
		// readers and not recording it at all. Counted rather than logged per
		// connection, because the traffic this exists for arrives thousands of
		// times an hour and a line each would be its own noise problem.
		h.countDrop(ra.IP.String())
		conn.Close()
		return
	}

	connID := uuid.New().String()
	h.connections.Store(connID, conn)

	defer func() {
		h.connections.Delete(connID)
		conn.Close()
	}()

	origDst, err := socket.GetOriginalDstAuto(conn)
	if err != nil {
		h.logger.Debug("network", fmt.Sprintf("failed to get original destination: %v", err))
		return
	}

	remoteAddr := conn.RemoteAddr().(*net.TCPAddr)

	var stream *tls.Stream
	var tlsALPN string
	var tlsServerName string
	var tlsVersion string
	var tlsCipherSuite string
	var tlsClientSubject string
	var tlsClientIssuer string
	var tlsClientNotBefore int64
	var tlsClientNotAfter int64
	var tlsJA4 string
	var tlsJA3 string
	var tlsHelloHex string
	var tlsSupportedProtocols []string
	if h.tlsHandler != nil {
		var clientHello tls.ClientHelloInfo
		wrappedConn, isTLS, err := h.tlsHandler.WrapConnection(conn, &clientHello)
		if err != nil {
			if isTLS {
				return // Silently fail TLS handshake
			}
			// Not a TLS connection, continue with plain TCP
			stream = tls.NewPlainStream(conn)
		} else {
			if isTLS {
				// If the wrapped connection is a crypto/tls.Conn we can extract ALPN/SNI and other TLS metadata
				if tc, ok := wrappedConn.(*cryptotls.Conn); ok {
					cs := tc.ConnectionState()
					tlsALPN = cs.NegotiatedProtocol
					tlsServerName = cs.ServerName
					switch cs.Version {
					case cryptotls.VersionTLS10:
						tlsVersion = "TLSv1.0"
					case cryptotls.VersionTLS11:
						tlsVersion = "TLSv1.1"
					case cryptotls.VersionTLS12:
						tlsVersion = "TLSv1.2"
					case cryptotls.VersionTLS13:
						tlsVersion = "TLSv1.3"
					default:
						tlsVersion = ""
					}
					tlsCipherSuite = cryptotls.CipherSuiteName(cs.CipherSuite)

					// Capture client certificate details when mTLS is used
					if len(cs.PeerCertificates) > 0 {
						cert := cs.PeerCertificates[0]
						tlsClientSubject = cert.Subject.String()
						if cert.Issuer.String() != "" {
							tlsClientIssuer = cert.Issuer.String()
						}
						if !cert.NotBefore.IsZero() {
							tlsClientNotBefore = cert.NotBefore.Unix()
						}
						if !cert.NotAfter.IsZero() {
							tlsClientNotAfter = cert.NotAfter.Unix()
						}
					}
				}
				stream = tls.NewTLSStream(wrappedConn)
				tlsJA4 = clientHello.JA4
				tlsJA3 = clientHello.JA3
				if len(clientHello.HelloRaw) > 0 {
					tlsHelloHex = hex.EncodeToString(clientHello.HelloRaw)
				}
				tlsSupportedProtocols = clientHello.SupportedProtocols
			} else {
				stream = tls.NewPlainStream(wrappedConn)
			}
		}
	} else {
		stream = tls.NewPlainStream(conn)
	}
	defer stream.Close()

	// Low-interaction protocol persona keyed by the original destination port
	// (preserved across the iptables REDIRECT via SO_ORIGINAL_DST).
	// personaDefault leaves all existing behaviour unchanged.
	persona := personaForPort(int(origDst.Port))
	stage := 0
	// Server-speaks-first protocols (telnet, FTP, SMTP, POP3, IMAP) expect the
	// server to send a banner/prompt before the client sends anything, so emit it
	// before the read loop; the client then proceeds to send credentials/commands.
	if greeting := personaGreeting(persona); greeting != nil {
		conn.SetWriteDeadline(time.Now().Add(h.writeTimeout))
		if _, err := stream.Write(greeting); err != nil {
			return
		}
	}

	sessionID := uuid.New().String()
	buffer := make([]byte, 16384)

	// Behavioral metadata: cumulative within the session up to each emitted record.
	connStart := time.Now()
	var bytesIn, bytesOut int64
	recordSeq := 0

	for {
		conn.SetReadDeadline(time.Now().Add(h.readTimeout))

		n, err := stream.Read(buffer)
		if err != nil {
			return
		}

		if n == 0 {
			return
		}

		// Coalesce TCP segments arriving in quick succession to avoid split log events.
		payloadBytes := make([]byte, n)
		copy(payloadBytes, buffer[:n])
		conn.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
		for {
			n2, err2 := stream.Read(buffer)
			if n2 > 0 {
				payloadBytes = append(payloadBytes, buffer[:n2]...)
			}
			if err2 != nil {
				break
			}
		}
		conn.SetReadDeadline(time.Time{})

		// SSH Hassh requires client banner and KEXINIT. Protocol has client send banner then wait for server banner before KEXINIT.
		// When we only have the banner, send a minimal server banner and read again to capture KEXINIT.
		if fingerprint.IsSSHClientPayload(payloadBytes) && fingerprint.Hassh(payloadBytes) == "" {
			const sshServerBanner = "SSH-2.0-spip\r\n"
			conn.SetWriteDeadline(time.Now().Add(h.writeTimeout))
			if _, errW := stream.Write([]byte(sshServerBanner)); errW != nil {
				// Use banner-only payload
			} else {
				conn.SetReadDeadline(time.Now().Add(2 * time.Second))
				n2, err2 := stream.Read(buffer)
				conn.SetReadDeadline(time.Time{})
				if err2 == nil && n2 > 0 {
					payloadBytes = append(payloadBytes, buffer[:n2]...)
				}
			}
		}
		bytesIn += int64(len(payloadBytes))
		recordSeq++
		var response []byte
		done := false
		switch {
		case persona == personaTelnet:
			// Re-prompt (don't advance) on pure IAC option negotiation so we
			// only step the login flow on real keystrokes.
			if !hasPrintable(payloadBytes) {
				if stage == 0 {
					response = []byte("login: ")
				} else {
					response = []byte("Password: ")
				}
			} else {
				response, done = telnetReply(&stage)
			}
		case isBannerPersona(persona):
			// FTP/SMTP/POP3/IMAP: canned status lines keep the scanner sending
			// its credentials / envelope / commands, which we capture in payload.
			response, done = bannerReply(persona, &stage)
		case persona == personaRedis || looksLikeRedis(payloadBytes):
			// Minimal RESP replies keep the attacker sending its full command
			// sequence (CONFIG SET / SLAVEOF / MODULE LOAD / cron payloads).
			response = redisReply(payloadBytes)
		case isHTTPRequest(payloadBytes):
			response = handleHTTPRequest(payloadBytes, remoteAddr.IP.String())
		default:
			// For non-HTTP requests, return just the IP
			response = []byte(remoteAddr.IP.String())
		}
		conn.SetWriteDeadline(time.Now().Add(h.writeTimeout))
		if _, err := stream.Write(response); err != nil {
			return
		}
		bytesOut += int64(len(response))
		// Community ID uses original destination (before iptables REDIRECT) so flow hash matches other tools.
		communityID := fingerprint.CommunityIDV1(remoteAddr.IP.String(), origDst.IP.String(), uint16(remoteAddr.Port), origDst.Port, 6, h.communityIDSeed)
		var sshHassh string
		if fingerprint.IsSSHClientPayload(payloadBytes) {
			sshHassh = fingerprint.Hassh(payloadBytes)
		}
		connData := &logging.ConnectionData{
			Name:                  h.name,
			Timestamp:             time.Now().Unix(),
			Payload:               string(payloadBytes),
			PayloadHex:            hex.EncodeToString(payloadBytes),
			SourceIP:              remoteAddr.IP.String(),
			SourcePort:            uint16(remoteAddr.Port),
			DestinationIP:         origDst.IP.String(),
			DestinationPort:       origDst.Port,
			SessionID:             sessionID,
			IsTLS:                 stream.IsTLS(),
			TLSALPN:               tlsALPN,
			TLSServerName:         tlsServerName,
			TLSVersion:            tlsVersion,
			TLSCipherSuite:        tlsCipherSuite,
			TLSClientSubject:      tlsClientSubject,
			TLSClientIssuer:       tlsClientIssuer,
			TLSClientNotBefore:    tlsClientNotBefore,
			TLSClientNotAfter:     tlsClientNotAfter,
			CommunityID:           communityID,
			TLSSupportedProtocols: tlsSupportedProtocols,
			TLSJA4:                tlsJA4,
			TLSJA3:                tlsJA3,
			TLSClientHelloHex:     tlsHelloHex,
			SSHHassh:              sshHassh,
			DurationMs:            time.Since(connStart).Milliseconds(),
			BytesIn:               bytesIn,
			BytesOut:              bytesOut,
			RecordSeq:             recordSeq,
		}

		if err := h.logger.LogConnection(connData); err != nil {
			h.logger.Error("network", fmt.Sprintf("Failed to log connection data: %v", err))
		}

		// Telnet / banner protocols: after the scripted exchange ends (e.g. the
		// password was captured), drop the connection like a real failed login
		// rather than looping further.
		if done {
			return
		}
	}
}
