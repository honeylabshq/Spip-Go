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
	"strings"
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

// TestRequestClientCert verifies ClientAuth=RequestClientCert: the server asks
// for a client certificate but does not require it. A client presenting none
// must still complete the handshake (the critical safety property — most
// scanners have no cert), and a client that does present one must have it
// captured in ConnectionState().PeerCertificates so it can be logged.
func TestRequestClientCert(t *testing.T) {
	certPath, keyPath := generateTestCertificate(t)
	defer os.RemoveAll(filepath.Dir(certPath))

	handler, err := NewTLSHandler(&Config{CertPath: certPath, KeyPath: keyPath})
	if err != nil {
		t.Fatalf("NewTLSHandler: %v", err)
	}

	// runOnce performs one client/server TLS handshake through the handler and
	// reports how many client certs the server observed (and the first subject).
	runOnce := func(t *testing.T, clientCerts []tls.Certificate) (int, string) {
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("listen: %v", err)
		}
		defer listener.Close()

		type result struct {
			n       int
			subject string
			err     error
		}
		resCh := make(chan result, 1)
		go func() {
			conn, err := listener.Accept()
			if err != nil {
				resCh <- result{err: err}
				return
			}
			defer conn.Close()
			wrapped, isTLS, err := handler.WrapConnection(conn, nil)
			if err != nil || !isTLS {
				resCh <- result{err: err}
				return
			}
			defer wrapped.Close()
			// Drive the handshake to completion so PeerCertificates is populated.
			buf := make([]byte, 64)
			_, _ = wrapped.Read(buf)
			tc, ok := wrapped.(*tls.Conn)
			if !ok {
				resCh <- result{n: -1}
				return
			}
			cs := tc.ConnectionState()
			subj := ""
			if len(cs.PeerCertificates) > 0 {
				subj = cs.PeerCertificates[0].Subject.String()
			}
			resCh <- result{n: len(cs.PeerCertificates), subject: subj}
		}()

		clientConn, err := tls.Dial("tcp", listener.Addr().String(), &tls.Config{
			InsecureSkipVerify: true,
			Certificates:       clientCerts,
		})
		if err != nil {
			t.Fatalf("client handshake failed (must always succeed): %v", err)
		}
		_, _ = clientConn.Write([]byte("x")) // unblock the server Read
		clientConn.Close()

		select {
		case r := <-resCh:
			if r.err != nil {
				t.Fatalf("server error: %v", r.err)
			}
			return r.n, r.subject
		case <-time.After(3 * time.Second):
			t.Fatal("timeout waiting for handshake")
			return 0, ""
		}
	}

	t.Run("no client cert still handshakes", func(t *testing.T) {
		if n, _ := runOnce(t, nil); n != 0 {
			t.Errorf("expected 0 peer certs, got %d", n)
		}
	})

	t.Run("client cert is captured", func(t *testing.T) {
		clientCert, err := tls.LoadX509KeyPair(certPath, keyPath)
		if err != nil {
			t.Fatalf("load client cert: %v", err)
		}
		n, subj := runOnce(t, []tls.Certificate{clientCert})
		if n < 1 {
			t.Fatalf("expected >=1 peer cert, got %d", n)
		}
		if !strings.Contains(subj, "Spip Test") {
			t.Errorf("peer cert subject = %q, want it to contain %q", subj, "Spip Test")
		}
	})
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
