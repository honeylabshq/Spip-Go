package network

import (
	"bytes"
	cryptotls "crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"syscall"
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
	logger            logging.Logger
	tlsHandler        *tls.TLSHandler
	limiter           *rate.Limiter
	connections       sync.Map
	readTimeout       time.Duration
	writeTimeout      time.Duration
	name              string
	communityIDSeed   uint16
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

// isConnectionClosed checks if an error indicates a closed connection
func isConnectionClosed(err error) bool {
	if err == nil {
		return false
	}
	if err == io.EOF {
		return true
	}
	if netErr, ok := err.(net.Error); ok {
		return netErr.Timeout() || netErr.Temporary()
	}
	// Common scanner behavior: connection reset or broken pipe
	if errors.Is(err, syscall.ECONNRESET) || errors.Is(err, syscall.EPIPE) {
		return true
	}
	// Fallback string checks for platforms or wrappers that expose textual errors
	if strings.Contains(err.Error(), "connection reset by peer") || strings.Contains(err.Error(), "broken pipe") {
		return true
	}
	return false
}

// shouldLogError determines if an error should be logged
func shouldLogError(err error) bool {
	if err == nil {
		return false
	}

	// Only log errors that are not connection-related
	if strings.Contains(err.Error(), "tls:") ||
		strings.Contains(err.Error(), "read:") ||
		strings.Contains(err.Error(), "write:") ||
		strings.Contains(err.Error(), "i/o timeout") ||
		err == io.EOF ||
		isConnectionClosed(err) {
		return false
	}

	// Log only truly unexpected errors
	return true
}

// classifyConnectionError categorizes connection errors for appropriate logging
func classifyConnectionError(err error) (severity string, isExpected bool) {
	if err == nil {
		return "", true
	}

	// Common scanner behaviors - debug level
	if err == io.EOF || errors.Is(err, syscall.ECONNRESET) || errors.Is(err, syscall.EPIPE) || strings.Contains(err.Error(), "i/o timeout") {
		return "debug", true
	}

	// Expected TLS probing behaviors - info level
	if strings.Contains(err.Error(), "tls: first record does not look like a TLS handshake") ||
		strings.Contains(err.Error(), "tls: bad certificate") ||
		strings.Contains(err.Error(), "tls: handshake failure") ||
		strings.Contains(err.Error(), "tls: client offered only unsupported versions") ||
		strings.Contains(err.Error(), "tls: no cipher suite supported") {
		return "info", true
	}

	// Network timeouts and temporary errors - debug level
	if netErr, ok := err.(net.Error); ok {
		if netErr.Timeout() || netErr.Temporary() {
			return "debug", true
		}
	}

	// Anything else might be worth investigating
	return "error", false
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

	connID := uuid.New().String()
	h.connections.Store(connID, conn)

	done := make(chan struct{})

	defer func() {
		close(done)
		h.connections.Delete(connID)
		conn.Close()
	}()

	origDst, err := socket.GetOriginalDst(conn)
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
				tlsSupportedProtocols = clientHello.SupportedProtocols
			} else {
				stream = tls.NewPlainStream(wrappedConn)
			}
		}
	} else {
		stream = tls.NewPlainStream(conn)
	}
	defer stream.Close()

	sessionID := uuid.New().String()
	buffer := make([]byte, 16384)

	for {
		select {
		case <-done:
			return
		default:
			conn.SetReadDeadline(time.Now().Add(h.readTimeout))

			n, err := stream.Read(buffer)
			if err != nil {
				return
			}

			if n == 0 {
				return
			}

			var response []byte
			if isHTTPRequest(buffer[:n]) {
				response = handleHTTPRequest(buffer[:n], remoteAddr.IP.String())
			} else {
				// For non-HTTP requests, return just the IP
				response = []byte(remoteAddr.IP.String())
			}

			conn.SetWriteDeadline(time.Now().Add(h.writeTimeout))

			if _, err := stream.Write(response); err != nil {
				return
			}

			payloadBytes := buffer[:n]
			// Community ID uses original destination (before iptables REDIRECT) so flow hash matches other tools.
			communityID := fingerprint.CommunityIDV1(remoteAddr.IP.String(), origDst.IP.String(), uint16(remoteAddr.Port), origDst.Port, 6, h.communityIDSeed)
			var sshHassh string
			if fingerprint.IsSSHClientPayload(payloadBytes) {
				sshHassh = fingerprint.Hassh(payloadBytes)
			}
			connData := &logging.ConnectionData{
				Name:                 h.name,
				Timestamp:            time.Now().Unix(),
				Payload:              string(payloadBytes),
				PayloadHex:           hex.EncodeToString(payloadBytes),
				SourceIP:             remoteAddr.IP.String(),
				SourcePort:           uint16(remoteAddr.Port),
				DestinationIP:        origDst.IP.String(),
				DestinationPort:      origDst.Port,
				SessionID:            sessionID,
				IsTLS:                stream.IsTLS(),
				TLSALPN:              tlsALPN,
				TLSServerName:        tlsServerName,
				TLSVersion:           tlsVersion,
				TLSCipherSuite:       tlsCipherSuite,
				TLSClientSubject:     tlsClientSubject,
				TLSClientIssuer:      tlsClientIssuer,
				TLSClientNotBefore:   tlsClientNotBefore,
				TLSClientNotAfter:    tlsClientNotAfter,
				CommunityID:          communityID,
				TLSSupportedProtocols: tlsSupportedProtocols,
				TLSJA4:               tlsJA4,
				SSHHassh:             sshHassh,
			}

			if err := h.logger.LogConnection(connData); err != nil {
				h.logger.Error("network", fmt.Sprintf("Failed to log connection data: %v", err))
			}
		}
	}
}
