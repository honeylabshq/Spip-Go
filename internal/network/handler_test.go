package network

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"spip/internal/logging"
	spiptls "spip/internal/tls"
)

type mockLogger struct {
	connections []*logging.ConnectionData
	errors      []string
	debugs      []string
	infos       []string
	warns       []string
}

func (m *mockLogger) LogConnection(data *logging.ConnectionData) error {
	m.connections = append(m.connections, data)
	return nil
}

func (m *mockLogger) Log(level logging.LogLevel, target, message string) error {
	switch level {
	case logging.LevelDebug:
		m.Debug(target, message)
	case logging.LevelInfo:
		m.Info(target, message)
	case logging.LevelWarn:
		m.Warn(target, message)
	case logging.LevelError:
		m.Error(target, message)
	}
	return nil
}

func (m *mockLogger) Debug(target, message string) {
	m.debugs = append(m.debugs, message)
}

func (m *mockLogger) Info(target, message string) {
	m.infos = append(m.infos, message)
}

func (m *mockLogger) Warn(target, message string) {
	m.warns = append(m.warns, message)
}

func (m *mockLogger) Error(target, message string) {
	m.errors = append(m.errors, message)
}

func TestHandleConnection(t *testing.T) {
	// Create a TCP listener
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to create listener: %v", err)
	}
	defer listener.Close()

	// Create mock logger
	mock := &mockLogger{
		connections: make([]*logging.ConnectionData, 0),
		errors:      make([]string, 0),
	}

	// Create network handler
	handler := NewHandler(mock, nil, 20, 50000, 30*time.Second, 10*time.Second, "test-agent", 0)

	// Accept connection in goroutine
	connChan := make(chan *net.TCPConn)
	errChan := make(chan error)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			errChan <- err
			return
		}
		tcpConn, ok := conn.(*net.TCPConn)
		if !ok {
			errChan <- err
			return
		}
		connChan <- tcpConn
	}()

	// Connect to server
	client, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatalf("Failed to connect: %v", err)
	}
	defer client.Close()

	// Get server connection
	var serverConn *net.TCPConn
	select {
	case serverConn = <-connChan:
	case err := <-errChan:
		t.Fatalf("Failed to accept connection: %v", err)
	case <-time.After(time.Second):
		t.Fatal("Timeout waiting for connection")
	}

	// Handle connection in goroutine
	done := make(chan struct{})
	go func() {
		handler.HandleConnection(serverConn)
		close(done)
	}()

	// Send test data
	testData := []byte("Hello, TCP!")
	if _, err := client.Write(testData); err != nil {
		t.Fatalf("Failed to write to client: %v", err)
	}

	// Wait a small amount of time for the server to read the data
	time.Sleep(100 * time.Millisecond)

	// Close the client connection gracefully
	client.(*net.TCPConn).CloseWrite()

	// Wait for handler to finish
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("Timeout waiting for handler to finish")
	}

	// Verify connection data
	if len(mock.connections) != 1 {
		t.Fatalf("Expected 1 connection log, got %d", len(mock.connections))
	}

	conn := mock.connections[0]
	if conn.Payload != string(testData) {
		t.Errorf("Expected payload %q, got %q", string(testData), conn.Payload)
	}
	if conn.IsTLS {
		t.Error("Expected non-TLS connection")
	}
	if len(mock.errors) > 0 {
		t.Errorf("Unexpected errors: %v", mock.errors)
	}
}

func TestHandleConnectionWithTLS(t *testing.T) {
	// Create temporary directory for certificates
	tmpDir, err := os.MkdirTemp("", "spip-network-test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	// Generate test certificate
	cert, err := generateTestCertificate(t, tmpDir)
	if err != nil {
		t.Fatalf("Failed to generate certificate: %v", err)
	}

	// Create TLS handler
	tlsHandler, err := spiptls.NewTLSHandler(&spiptls.Config{
		CertPath: cert.certPath,
		KeyPath:  cert.keyPath,
	})
	if err != nil {
		t.Fatalf("Failed to create TLS handler: %v", err)
	}

	// Create TCP listener
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to create listener: %v", err)
	}
	defer listener.Close()

	// Create mock logger
	mock := &mockLogger{
		connections: make([]*logging.ConnectionData, 0),
		errors:      make([]string, 0),
	}

	// Create network handler
	handler := NewHandler(mock, tlsHandler, 20, 50000, 30*time.Second, 10*time.Second, "test-agent", 0)

	// Start server in goroutine
	serverDone := make(chan struct{})
	go func() {
		defer close(serverDone)
		conn, err := listener.Accept()
		if err != nil {
			t.Errorf("Failed to accept: %v", err)
			return
		}
		tcpConn, ok := conn.(*net.TCPConn)
		if !ok {
			t.Errorf("Failed to convert to TCP connection")
			return
		}
		handler.HandleConnection(tcpConn)
	}()

	// Connect to server with TLS
	client, err := tls.Dial("tcp", listener.Addr().String(), &tls.Config{
		InsecureSkipVerify: true,
	})
	if err != nil {
		t.Fatalf("Failed to connect: %v", err)
	}
	defer client.Close()

	// Send test data
	testData := []byte("Hello, TLS!")
	if _, err := client.Write(testData); err != nil {
		t.Fatalf("Failed to write to client: %v", err)
	}

	// Close client to signal end of data
	client.Close()

	// Wait for server to finish
	select {
	case <-serverDone:
	case <-time.After(2 * time.Second): // Increased timeout for TLS handshake
		t.Fatal("Timeout waiting for server to finish")
	}

	// Verify connection data
	if len(mock.connections) != 1 {
		t.Fatalf("Expected 1 connection log, got %d", len(mock.connections))
	}

	conn := mock.connections[0]
	if conn.Payload != string(testData) {
		t.Errorf("Expected payload %q, got %q", string(testData), conn.Payload)
	}
	if !conn.IsTLS {
		t.Error("Expected TLS connection")
	}
	if len(mock.errors) > 0 {
		t.Errorf("Unexpected errors: %v", mock.errors)
	}
}

type testCert struct {
	certPath string
	keyPath  string
}

func generateTestCertificate(t *testing.T, dir string) (*testCert, error) {
	// Generate private key
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}

	// Create certificate template
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"Test"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	// Create certificate
	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}

	// Write certificate to file
	certPath := filepath.Join(dir, "cert.pem")
	certOut, err := os.Create(certPath)
	if err != nil {
		return nil, err
	}
	pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	certOut.Close()

	// Write private key to file
	keyPath := filepath.Join(dir, "key.pem")
	keyOut, err := os.Create(keyPath)
	if err != nil {
		return nil, err
	}
	keyBytes := x509.MarshalPKCS1PrivateKey(key)
	pem.Encode(keyOut, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: keyBytes})
	keyOut.Close()

	return &testCert{
		certPath: certPath,
		keyPath:  keyPath,
	}, nil
}
