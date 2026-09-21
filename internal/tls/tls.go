package tls

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"github.com/psanford/tlsfingerprint"
	"io"
	"net"
)

// Config represents TLS configuration
type Config struct {
	CertPath string
	KeyPath  string
	// CaptureClientHello keeps the raw ClientHello on each TLS connection.
	// Off leaves HelloRaw nil and changes nothing else.
	CaptureClientHello bool
}

// TLSHandler handles TLS connections
type TLSHandler struct {
	config       *tls.Config
	captureHello bool
}

// NewTLSHandler creates a new TLS handler
func NewTLSHandler(cfg *Config) (*TLSHandler, error) {
	cert, err := tls.LoadX509KeyPair(cfg.CertPath, cfg.KeyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load TLS certificate: %w", err)
	}

	config := &tls.Config{
		Certificates: []tls.Certificate{cert},
		// Ask the client for a certificate but don't require or verify it: the
		// handshake still completes for the ~all clients that present none, and
		// for the rare client that does we capture its cert (subject/issuer/
		// validity) for tls.client.client_certificate.*. Never RequireAnyClientCert
		// here — that would break the handshake for normal scanners.
		ClientAuth: tls.RequestClientCert,
		MinVersion: tls.VersionTLS10,
		MaxVersion: tls.VersionTLS13,
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

	return &TLSHandler{config: config, captureHello: cfg.CaptureClientHello}, nil
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
	JA4                string   // JA4 fingerprint string
	JA3                string   // JA3 fingerprint (MD5 hash) — legacy, still keyed by most TI feeds
	SupportedProtocols []string // ALPN protocols advertised by client (tls.client.supported_protocols)

	// HelloRaw is the ClientHello record exactly as it arrived, header
	// included. It is kept because every fingerprint above is lossy and
	// throwing the input away makes them impossible to check or replace:
	// JA4 sorts the extension list, JA3 keeps its order, and neither keeps
	// GREASE placement or the extension bodies. A sensor that stores only
	// its own conclusions cannot answer a question nobody asked yet.
	//
	// nil when capture is disabled or the record was not fully read.
	HelloRaw []byte
}

// MaxClientHelloBytes bounds what a single peer can make us keep. A real
// ClientHello is a few hundred bytes; 16 KiB is the TLS record ceiling, so
// this accepts every legitimate hello and refuses to grow with a hostile one.
const MaxClientHelloBytes = 16 * 1024

// helloRecorder copies everything read from the peer into buf so the raw
// ClientHello survives the fingerprinter consuming it. The fingerprinter
// reads through a bufio.Reader, which may pull more than the record, so what
// is recorded here is trimmed to the record length by clientHelloRecord.
type helloRecorder struct {
	net.Conn
	buf []byte
}

func (c *helloRecorder) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	if n > 0 && len(c.buf) < MaxClientHelloBytes {
		room := MaxClientHelloBytes - len(c.buf)
		if n < room {
			room = n
		}
		c.buf = append(c.buf, p[:room]...)
	}
	return n, err
}

// clientHelloRecord trims recorded bytes to exactly one TLS record: a 5-byte
// header whose last two bytes give the payload length. Returns nil unless the
// whole record is present, so a partial read is never stored as if it were a
// complete hello.
func clientHelloRecord(b []byte) []byte {
	if len(b) < 5 || b[0] != 0x16 {
		return nil
	}
	total := 5 + int(b[3])<<8 | int(b[4])
	if total < 5 || total > len(b) {
		return nil
	}
	out := make([]byte, total)
	copy(out, b[:total])
	return out
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

	var src net.Conn = connWithPrefix
	var rec *helloRecorder
	if h.captureHello {
		rec = &helloRecorder{Conn: connWithPrefix}
		src = rec
	}

	fp, replayConn, err := tlsfingerprint.FingerprintConn(src)
	if err != nil {
		return nil, true, fmt.Errorf("TLS ClientHello fingerprint: %w", err)
	}
	if out != nil {
		out.JA4 = fp.JA4String()
		out.JA3 = fp.JA3Hash()
		out.SupportedProtocols = fp.ALPNProtocols
		if rec != nil {
			out.HelloRaw = clientHelloRecord(rec.buf)
		}
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
