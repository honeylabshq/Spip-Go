package tls

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// generateTestCertificate generates a self-signed certificate for testing
func generateTestCertificate(t *testing.T) (certPath, keyPath string) {
	// Create temporary directory
	tmpDir, err := os.MkdirTemp("", "spip-tls-test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}

	// Generate private key
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate private key: %v", err)
	}

	// Create certificate template
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"Spip Test"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
	}

	// Create certificate
	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	if err != nil {
		t.Fatalf("Failed to create certificate: %v", err)
	}

	// Write certificate to file
	certPath = filepath.Join(tmpDir, "cert.pem")
	certOut, err := os.Create(certPath)
	if err != nil {
		t.Fatalf("Failed to create cert.pem: %v", err)
	}
	if err := pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes}); err != nil {
		t.Fatalf("Failed to write cert.pem: %v", err)
	}
	certOut.Close()

	// Write private key to file
	keyPath = filepath.Join(tmpDir, "key.pem")
	keyOut, err := os.Create(keyPath)
	if err != nil {
		t.Fatalf("Failed to create key.pem: %v", err)
	}
	privBytes, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		t.Fatalf("Failed to marshal private key: %v", err)
	}
	if err := pem.Encode(keyOut, &pem.Block{Type: "PRIVATE KEY", Bytes: privBytes}); err != nil {
		t.Fatalf("Failed to write key.pem: %v", err)
	}
	keyOut.Close()

	return certPath, keyPath
}

func TestNewTLSHandler(t *testing.T) {
	certPath, keyPath := generateTestCertificate(t)
	defer os.RemoveAll(filepath.Dir(certPath))

	tests := []struct {
		name    string
		config  *Config
		wantErr bool
	}{
		{
			name: "valid certificate",
			config: &Config{
				CertPath: certPath,
				KeyPath:  keyPath,
			},
			wantErr: false,
		},
		{
			name: "invalid certificate path",
			config: &Config{
				CertPath: "nonexistent.pem",
				KeyPath:  keyPath,
			},
			wantErr: true,
		},
		{
			name: "invalid key path",
			config: &Config{
				CertPath: certPath,
				KeyPath:  "nonexistent.pem",
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			handler, err := NewTLSHandler(tt.config)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewTLSHandler() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && handler == nil {
				t.Error("NewTLSHandler() returned nil handler")
			}
		})
	}
}

func TestTLSStream(t *testing.T) {
	certPath, keyPath := generateTestCertificate(t)
	defer os.RemoveAll(filepath.Dir(certPath))

	// Create TLS handler
	handler, err := NewTLSHandler(&Config{
		CertPath: certPath,
		KeyPath:  keyPath,
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

	// Start server in goroutine
	serverDone := make(chan struct{})
	go func() {
		defer close(serverDone)
		conn, err := listener.Accept()
		if err != nil {
			t.Errorf("Failed to accept: %v", err)
			return
		}
		defer conn.Close()

		// Wrap server connection with TLS
		tlsConn, isTLS, err := handler.WrapConnection(conn, nil)
		if err != nil {
			t.Errorf("Failed to wrap connection: %v", err)
			return
		}
		if !isTLS {
			t.Error("Expected TLS connection")
			return
		}
		defer tlsConn.Close()

		// Create TLS stream
		stream := NewTLSStream(tlsConn)
		if !stream.IsTLS() {
			t.Error("Stream should be TLS")
			return
		}

		// Read test data
		buf := make([]byte, 1024)
		n, err := stream.Read(buf)
		if err != nil {
			t.Errorf("Failed to read: %v", err)
			return
		}

		// Echo data back
		if _, err := stream.Write(buf[:n]); err != nil {
			t.Errorf("Failed to write back: %v", err)
			return
		}
	}()

	// Connect as client
	clientConn, err := tls.Dial("tcp", listener.Addr().String(), &tls.Config{
		InsecureSkipVerify: true,
	})
	if err != nil {
		t.Fatalf("Failed to connect: %v", err)
	}
	defer clientConn.Close()

	// Test data transfer
	testData := []byte("Hello, TLS!")
	if _, err := clientConn.Write(testData); err != nil {
		t.Fatalf("Failed to write to server: %v", err)
	}

	// Read response
	response := make([]byte, len(testData))
	if _, err := io.ReadFull(clientConn, response); err != nil {
		t.Fatalf("Failed to read from server: %v", err)
	}

	if string(response) != string(testData) {
		t.Errorf("Got response %q, want %q", string(response), string(testData))
	}

	// Wait for server to finish
	select {
	case <-serverDone:
	case <-time.After(time.Second):
		t.Fatal("Timeout waiting for server to finish")
	}
}

func TestPlainStream(t *testing.T) {
	// Create TCP connection pair
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to create listener: %v", err)
	}
	defer listener.Close()

	// Accept connection in goroutine
	connChan := make(chan net.Conn)
	errChan := make(chan error)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			errChan <- err
			return
		}
		connChan <- conn
	}()

	// Connect to server
	clientConn, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatalf("Failed to connect: %v", err)
	}
	defer clientConn.Close()

	// Get server connection
	var serverConn net.Conn
	select {
	case serverConn = <-connChan:
	case err := <-errChan:
		t.Fatalf("Failed to accept connection: %v", err)
	case <-time.After(time.Second):
		t.Fatal("Timeout waiting for connection")
	}

	// Create plain stream
	stream := NewPlainStream(serverConn)
	if stream.IsTLS() {
		t.Error("Stream should not be TLS")
	}

	// Test data transfer
	testData := []byte("Hello, TCP!")
	go func() {
		if _, err := clientConn.Write(testData); err != nil {
			t.Errorf("Failed to write to client: %v", err)
		}
	}()

	buf := make([]byte, len(testData))
	n, err := stream.Read(buf)
	if err != nil {
		t.Fatalf("Failed to read from stream: %v", err)
	}
	if n != len(testData) {
		t.Errorf("Read %d bytes, want %d", n, len(testData))
	}
	if string(buf) != string(testData) {
		t.Errorf("Read %q, want %q", string(buf), string(testData))
	}
}
