package tls

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"github.com/psanford/tlsfingerprint"
)

// Config represents TLS configuration
type Config struct {
	CertPath           string
	KeyPath            string
	InsecureSkipVerify bool
}

// TLSHandler handles TLS connections
type TLSHandler struct {
	config *tls.Config
}

// NewTLSHandler creates a new TLS handler
func NewTLSHandler(cfg *Config) (*TLSHandler, error) {
	cert, err := tls.LoadX509KeyPair(cfg.CertPath, cfg.KeyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load TLS certificate: %w", err)
	}

	config := &tls.Config{
		Certificates:       []tls.Certificate{cert},
		MinVersion:         tls.VersionTLS10,
		MaxVersion:         tls.VersionTLS13,
		InsecureSkipVerify: cfg.InsecureSkipVerify,
		CipherSuites: []uint16{
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
			tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
			tls.TLS_RSA_WITH_AES_256_CBC_SHA,
			tls.TLS_RSA_WITH_AES_128_CBC_SHA,
		},
	}

	return &TLSHandler{config: config}, nil
}

// IsTLSHandshake checks if the connection starts with a TLS handshake
func IsTLSHandshake(reader *bufio.Reader) bool {
	// TLS handshake starts with a record type of 0x16 (22)
	// followed by version (two bytes) and length (two bytes)
	firstByte, err := reader.Peek(1)
	if err != nil {
		return false
	}
	return len(firstByte) == 1 && firstByte[0] == 0x16
}

// ClientHelloInfo holds data extracted from the TLS ClientHello (for fingerprinting).
// Pass a non-nil pointer to WrapConnection to populate it when the connection is TLS.
type ClientHelloInfo struct {
	JA4                 string   // JA4 fingerprint string
	SupportedProtocols   []string // ALPN protocols advertised by client (tls.client.supported_protocols)
}

// prefixConn implements net.Conn by serving a prefix buffer first, then the underlying Conn.
type prefixConn struct {
	prefix []byte
	net.Conn
}

func (c *prefixConn) Read(p []byte) (n int, err error) {
	if len(c.prefix) > 0 {
		n = copy(p, c.prefix)
		c.prefix = c.prefix[n:]
		return n, nil
	}
	return c.Conn.Read(p)
}

// WrapConnection wraps a TCP connection with TLS if it detects a TLS handshake.
// If out is non-nil and the connection is TLS, out is populated with JA4 and supported ALPN protocols from the ClientHello.
func (h *TLSHandler) WrapConnection(conn net.Conn, out *ClientHelloInfo) (net.Conn, bool, error) {
	// Read exactly one byte so we can replay it; avoids bufio buffering extra bytes.
	buf := make([]byte, 1)
	if _, err := io.ReadFull(conn, buf); err != nil {
		return nil, false, fmt.Errorf("read first byte: %w", err)
	}
	if buf[0] != 0x16 {
		// Not TLS: replay the byte for the next reader
		return &prefixConn{prefix: buf, Conn: conn}, false, nil
	}
	connWithPrefix := &prefixConn{prefix: buf, Conn: conn}

	fp, replayConn, err := tlsfingerprint.FingerprintConn(connWithPrefix)
	if err != nil {
		return nil, true, fmt.Errorf("TLS ClientHello fingerprint: %w", err)
	}
	if out != nil {
		out.JA4 = fp.JA4String()
		out.SupportedProtocols = fp.ALPNProtocols
	}

	tlsConn := tls.Server(replayConn, h.config)
	if err := tlsConn.Handshake(); err != nil {
		return nil, true, fmt.Errorf("TLS handshake failed: %w", err)
	}
	return tlsConn, true, nil
}

// readWriteConn combines a buffered reader with a net.Conn
type readWriteConn struct {
	*bufio.Reader
	net.Conn
}

func (rwc *readWriteConn) Read(p []byte) (n int, err error) {
	return rwc.Reader.Read(p)
}

// Stream represents either a TLS or plain TCP connection
type Stream struct {
	conn  io.ReadWriteCloser
	isTLS bool
}

// NewTLSStream creates a new TLS stream
func NewTLSStream(conn net.Conn) *Stream {
	return &Stream{
		conn:  conn,
		isTLS: true,
	}
}

// NewPlainStream creates a new plain TCP stream
func NewPlainStream(conn net.Conn) *Stream {
	return &Stream{
		conn:  conn,
		isTLS: false,
	}
}

// Read implements io.Reader
func (s *Stream) Read(p []byte) (n int, err error) {
	return s.conn.Read(p)
}

// Write implements io.Writer
func (s *Stream) Write(p []byte) (n int, err error) {
	return s.conn.Write(p)
}

// Close implements io.Closer
func (s *Stream) Close() error {
	return s.conn.Close()
}

// IsTLS returns whether this is a TLS connection
func (s *Stream) IsTLS() bool {
	return s.isTLS
}
