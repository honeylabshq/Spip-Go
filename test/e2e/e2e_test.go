//go:build e2e
// +build e2e

// E2E tests require iptables and privileges. Run via scripts/run_e2e_tests.sh or scripts/run_e2e_in_container.sh.

package e2e

import (
	"bytes"
	"crypto/tls"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

const (
	testPort = 8080
	testHost = "127.0.0.1"
)

// testEnv represents a test environment
type testEnv struct {
	t           *testing.T
	configPath  string
	certPath    string
	keyPath     string
	spipProcess *os.Process
	stdout      *bytes.Buffer
	stdoutPipe  io.ReadCloser
	stdoutDone  chan struct{}
}

func startSpip(t *testing.T, configPath string) (*os.Process, *bytes.Buffer, io.ReadCloser) {
	// Get the path to the agent binary relative to the test directory
	agentPath := filepath.Join("..", "..", "spip-agent")
	cmd := exec.Command(agentPath, "-config", configPath)

	// Create a pipe for stdout
	stdout := &bytes.Buffer{}
	stdoutPipe, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatalf("Failed to create stdout pipe: %v", err)
	}

	// Set up command output
	cmd.Stderr = os.Stderr

	if err := cmd.Start(); err != nil {
		t.Fatalf("Failed to start spip-agent: %v", err)
	}

	// Start copying stdout in a goroutine
	go func() {
		io.Copy(io.MultiWriter(stdout, os.Stdout), stdoutPipe)
	}()

	// Wait for the server to start
	time.Sleep(time.Second)

	return cmd.Process, stdout, stdoutPipe
}

func setupTestEnv(t *testing.T, useTLS bool) *testEnv {
	// Build the agent first
	cmd := exec.Command("go", "build", "-o", filepath.Join("..", "..", "spip-agent"), filepath.Join("..", "..", "cmd", "spip-agent"))
	if err := cmd.Run(); err != nil {
		t.Fatalf("Failed to build spip-agent: %v", err)
	}

	if err := setupIptables(t); err != nil {
		t.Fatalf("Failed to setup iptables: %v", err)
	}

	var certPath, keyPath string
	if useTLS {
		certPath, keyPath = generateTestCertificate(t)
	}

	configPath := createTestConfig(t, useTLS, certPath, keyPath)
	process, stdout, stdoutPipe := startSpip(t, configPath)

	return &testEnv{
		t:           t,
		configPath:  configPath,
		certPath:    certPath,
		keyPath:     keyPath,
		spipProcess: process,
		stdout:      stdout,
		stdoutPipe:  stdoutPipe,
		stdoutDone:  make(chan struct{}),
	}
}

func (e *testEnv) cleanup() {
	if e.spipProcess != nil {
		stopSpip(e.t, e.spipProcess)
	}
	if e.configPath != "" {
		os.RemoveAll(filepath.Dir(e.configPath))
	}
	if e.certPath != "" {
		os.RemoveAll(filepath.Dir(e.certPath))
	}
	if e.stdoutPipe != nil {
		e.stdoutPipe.Close()
	}
	cleanupIptables(e.t)
}

// getStdout returns the current stdout buffer contents
func (e *testEnv) getStdout() string {
	// Wait for the pipe to close
	e.stdoutPipe.Close()
	return e.stdout.String()
}

func setupIptables(t *testing.T) error {
	// Clear any existing rules
	exec.Command("iptables", "-t", "nat", "-F").Run()

	// Add REDIRECT rule for all TCP traffic
	cmd := exec.Command("iptables", "-t", "nat", "-A", "OUTPUT",
		"-p", "tcp",
		"-d", testHost,
		"--dport", fmt.Sprintf("%d", testPort),
		"-j", "REDIRECT",
		"--to-port", fmt.Sprintf("%d", testPort))
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to add TCP redirect rule: %v", err)
	}

	return nil
}

func cleanupIptables(t *testing.T) {
	exec.Command("iptables", "-t", "nat", "-F").Run()
}

func generateTestCertificate(t *testing.T) (string, string) {
	// Create temporary directory
	tmpDir, err := os.MkdirTemp("", "spip-e2e-test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}

	// Generate test certificate using the helper from tls package
	certPath := filepath.Join(tmpDir, "cert.pem")
	keyPath := filepath.Join(tmpDir, "key.pem")

	// Use openssl to generate a self-signed certificate
	cmd := exec.Command("openssl", "req", "-x509", "-newkey", "rsa:2048",
		"-keyout", keyPath,
		"-out", certPath,
		"-days", "1",
		"-nodes",
		"-subj", "/CN=localhost")

	if err := cmd.Run(); err != nil {
		t.Fatalf("Failed to generate certificate: %v", err)
	}

	return certPath, keyPath
}

func createTestConfig(t *testing.T, useTLS bool, certPath, keyPath string) string {
	tmpDir, err := os.MkdirTemp("", "spip-config")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}

	configPath := filepath.Join(tmpDir, "config.toml")
	var configContent string

	if useTLS {
		configContent = fmt.Sprintf(`
		name = "e2e-agent"
		ip = "%s"
		port = %d
cert_path = "%s"
key_path = "%s"
`, testHost, testPort, certPath, keyPath)
	} else {
		configContent = fmt.Sprintf(`
		name = "e2e-agent"
		ip = "%s"
		port = %d
`, testHost, testPort)
	}

	if err := os.WriteFile(configPath, []byte(configContent), 0644); err != nil {
		t.Fatalf("Failed to write config file: %v", err)
	}

	return configPath
}

func createTestConfigWithLoom(t *testing.T, useTLS bool, certPath, keyPath, loomURL string) string {
	path := createTestConfig(t, useTLS, certPath, keyPath)
	if loomURL == "" {
		return path
	}
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read config: %v", err)
	}
	loomBlock := fmt.Sprintf(`
[loom]
enabled = true
url = "%s"
sensor_id = "e2e-sensor"
token = "e2e-token"
batch_size = 10
flush_interval = "2s"
`, loomURL)
	if err := os.WriteFile(path, append(content, []byte(loomBlock)...), 0644); err != nil {
		t.Fatalf("write config with loom: %v", err)
	}
	return path
}

func stopSpip(t *testing.T, process *os.Process) {
	if process != nil {
		process.Kill()
		process.Wait()
	}
}

func makeHTTPRequest(t *testing.T, useTLS bool, payload []byte) ([]byte, error) {
	var url string
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
		},
	}

	if useTLS {
		url = fmt.Sprintf("https://%s:%d", testHost, testPort)
	} else {
		url = fmt.Sprintf("http://%s:%d", testHost, testPort)
	}

	resp, err := client.Post(url, "text/plain", bytes.NewReader(payload))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	return io.ReadAll(resp.Body)
}

func makeTCPRequest(t *testing.T, useTLS bool, payload []byte) ([]byte, error) {
	var conn net.Conn
	var err error
	addr := net.JoinHostPort(testHost, fmt.Sprintf("%d", testPort))
	if useTLS {
		conn, err = tls.Dial("tcp", addr, &tls.Config{
			InsecureSkipVerify: true,
		})
	} else {
		conn, err = net.Dial("tcp", addr)
	}
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	if _, err := conn.Write(payload); err != nil {
		return nil, err
	}

	response := make([]byte, len(payload))
	n, err := conn.Read(response)
	if err != nil && err != io.EOF {
		return nil, err
	}

	return response[:n], nil
}

func TestTCPConnection(t *testing.T) {
	env := setupTestEnv(t, false)
	defer env.cleanup()

	// Test simple TCP connection
	payload := []byte("Hello TCP!")
	response, err := makeTCPRequest(t, false, payload)
	if err != nil {
		t.Fatalf("Failed to make TCP request: %v", err)
	}

	expectedResponse := []byte(testHost)
	if !bytes.Equal(response, expectedResponse) {
		t.Errorf("Got response %q, want %q", string(response), string(expectedResponse))
	}

	// HTTP over TCP (do before getStdout so both log lines are captured)
	httpPayload := []byte("GET / HTTP/1.1\r\nHost: localhost\r\n\r\n")
	response, err = makeHTTPRequest(t, false, httpPayload)
	if err != nil {
		t.Fatalf("Failed to make HTTP request: %v", err)
	}
	if !bytes.Equal(response, expectedResponse) {
		t.Errorf("Got HTTP response %q, want %q", string(response), string(expectedResponse))
	}

	// Give a small time for output to be written, then read stdout once (getStdout closes the pipe)
	time.Sleep(100 * time.Millisecond)
	output := env.getStdout()
	lines := strings.Split(output, "\n")
	var foundPayload bool

	for _, line := range lines {
		if line == "" {
			continue
		}

		entry, err := ParseLogLine(line)
		if err != nil {
			t.Errorf("Failed to parse JSON line %q: %v", line, err)
			continue
		}

		if entry.Payload == string(payload) {
			foundPayload = true
			// Validate JSON structure
			if err := ValidateLogEntry(entry, string(payload), false); err != nil {
				t.Errorf("Invalid JSON structure: %v", err)
			}

			// Additional ECS-specific expectations for non-HTTP TCP payloads
			if entry.SourceIP == "" || entry.DestinationIP == "" {
				t.Errorf("expected source and destination IPs to be set, got src=%q dst=%q", entry.SourceIP, entry.DestinationIP)
			}
			if entry.PayloadHex == "" {
				t.Errorf("expected PayloadHex (event.original_payload_hex) to be populated for payload %q", entry.Payload)
			}
			// Fingerprinting: Community ID should be set (format "1:<base64>")
			if entry.CommunityID == "" {
				t.Error("expected network.community_id to be set for TCP connection")
			} else if !strings.HasPrefix(entry.CommunityID, "1:") {
				t.Errorf("expected network.community_id to start with '1:', got %q", entry.CommunityID)
			}
			break
		}
	}

	if !foundPayload {
		t.Error("Did not find expected payload in JSON output")
	}

	// Fingerprinting: at least one HTTP log line should have JA4H (we already did HTTP request above)
	var foundHTTPJA4H bool
	for _, line := range strings.Split(output, "\n") {
		if line == "" {
			continue
		}
		entry, err := ParseLogLine(line)
		if err != nil {
			continue
		}
		if entry.HTTPJA4H != "" {
			foundHTTPJA4H = true
			break
		}
	}
	if !foundHTTPJA4H {
		t.Error("expected http.request.hash.ja4h to be set for HTTP request")
	}
}

func TestTLSConnection(t *testing.T) {
	env := setupTestEnv(t, true)
	defer env.cleanup()

	// Test simple TLS connection
	payload := []byte("Hello TLS!")
	response, err := makeTCPRequest(t, true, payload)
	if err != nil {
		t.Fatalf("Failed to make TLS request: %v", err)
	}

	expectedResponse := []byte(testHost)
	if !bytes.Equal(response, expectedResponse) {
		t.Errorf("Got response %q, want %q", string(response), string(expectedResponse))
	}

	// Fingerprinting: TLS connection should have community_id and tls.client (JA4 and/or server_name)
	time.Sleep(100 * time.Millisecond)
	output := env.getStdout()
	var foundTLS bool
	for _, line := range strings.Split(output, "\n") {
		if line == "" {
			continue
		}
		entry, err := ParseLogLine(line)
		if err != nil {
			continue
		}
		if entry.Payload == string(payload) && entry.IsTLS {
			foundTLS = true
			if entry.CommunityID == "" || !strings.HasPrefix(entry.CommunityID, "1:") {
				t.Errorf("expected network.community_id for TLS connection, got %q", entry.CommunityID)
			}
			if entry.TLSJA4 == "" {
				t.Error("expected tls.client.hash.ja4 to be set for TLS connection")
			}
			break
		}
	}
	if !foundTLS {
		t.Error("did not find TLS payload in output to verify fingerprinting")
	}

	// Test HTTPS
	httpsPayload := []byte("POST /test HTTP/1.1\r\nHost: localhost\r\nContent-Length: 13\r\n\r\nHello HTTPS!")
	response, err = makeHTTPRequest(t, true, httpsPayload)
	if err != nil {
		t.Fatalf("Failed to make HTTPS request: %v", err)
	}

	if !bytes.Equal(response, expectedResponse) {
		t.Errorf("Got HTTPS response %q, want %q", string(response), string(expectedResponse))
	}
}

// buildSSHKEXINITPayload builds a minimal SSH-2.0 banner plus KEXINIT packet for Hassh fingerprinting.
func buildSSHKEXINITPayload() []byte {
	// SSH-2.0 banner
	banner := []byte("SSH-2.0-e2e_test\r\n")

	// 8 name-lists for KEXINIT (kex, server_host_key, enc_c2s, enc_s2c, mac_c2s, mac_s2c, comp_c2s, comp_s2c)
	names := []string{
		"curve25519-sha256",
		"ssh-ed25519",
		"chacha20-poly1305@openssh.com",
		"chacha20-poly1305@openssh.com",
		"umac-64-etm@openssh.com",
		"umac-64-etm@openssh.com",
		"none",
		"none",
	}
	var nlPart []byte
	for _, n := range names {
		b := []byte(n)
		var l [4]byte
		binary.BigEndian.PutUint32(l[:], uint32(len(b)))
		nlPart = append(nlPart, l[:]...)
		nlPart = append(nlPart, b...)
	}

	// KEXINIT: type (1) + cookie (16) + name-lists
	kexinit := make([]byte, 1+16+len(nlPart))
	kexinit[0] = 20 // SSH_MSG_KEXINIT
	// cookie 16 bytes (zeros)
	copy(kexinit[1:17], make([]byte, 16))
	copy(kexinit[17:], nlPart)

	// Packet: padding_length (1) + payload + padding; total length (excluding 4-byte length) must be multiple of 8
	payloadLen := 1 + len(kexinit)
	padLen := 8 - (payloadLen % 8)
	if padLen < 4 {
		padLen += 8
	}
	totalLen := payloadLen + padLen
	packet := make([]byte, 4+1+len(kexinit)+padLen)
	binary.BigEndian.PutUint32(packet[0:4], uint32(totalLen))
	packet[4] = byte(padLen)
	copy(packet[5:], kexinit)
	// padding bytes (zeros)

	return append(banner, packet...)
}

func TestSSHFingerprint(t *testing.T) {
	env := setupTestEnv(t, false)
	defer env.cleanup()

	sshPayload := buildSSHKEXINITPayload()
	response, err := makeTCPRequest(t, false, sshPayload)
	if err != nil {
		t.Fatalf("Failed to make TCP request with SSH payload: %v", err)
	}
	expectedResponse := []byte(testHost)
	if !bytes.Equal(response, expectedResponse) {
		t.Errorf("Got response %q, want %q", string(response), string(expectedResponse))
	}

	time.Sleep(100 * time.Millisecond)
	output := env.getStdout()
	var foundSSH bool
	for _, line := range strings.Split(output, "\n") {
		if line == "" {
			continue
		}
		entry, err := ParseLogLine(line)
		if err != nil {
			continue
		}
		if entry.SSHHassh != "" {
			foundSSH = true
			if len(entry.SSHHassh) != 32 {
				t.Errorf("expected ssh.client.hash.hassh to be 32-char hex, got %q", entry.SSHHassh)
			}
			break
		}
	}
	if !foundSSH {
		t.Error("expected ssh.client.hash.hassh to be set for SSH KEXINIT payload")
	}
}

// TestSSHFingerprintRealClient verifies ssh.client.hash.hassh is populated when the system ssh client connects.
func TestSSHFingerprintRealClient(t *testing.T) {
	if _, err := exec.LookPath("ssh"); err != nil {
		t.Skip("ssh not in PATH, skipping real-client test")
	}
	env := setupTestEnv(t, false)
	defer env.cleanup()

	// Redirect port 2222 to agent so ssh -p 2222 connects to the agent
	cmd := exec.Command("iptables", "-t", "nat", "-A", "OUTPUT",
		"-p", "tcp",
		"-d", testHost,
		"--dport", "2222",
		"-j", "REDIRECT",
		"--to-port", fmt.Sprintf("%d", testPort))
	if err := cmd.Run(); err != nil {
		t.Fatalf("failed to add iptables redirect for port 2222: %v", err)
	}

	// Run ssh; connection fails (agent is not an SSH server) but agent captures banner and KEXINIT for Hassh
	sshCmd := exec.Command("ssh",
		"-p", "2222",
		"-o", "StrictHostKeyChecking=no",
		"-o", "UserKnownHostsFile=/dev/null",
		"-o", "ConnectTimeout=3",
		"-o", "BatchMode=yes",
		testHost)
	_ = sshCmd.Run()

	time.Sleep(300 * time.Millisecond)
	output := env.getStdout()
	var hassh string
	for _, line := range strings.Split(output, "\n") {
		if line == "" {
			continue
		}
		entry, err := ParseLogLine(line)
		if err != nil {
			continue
		}
		if entry.DestinationPort == 2222 && entry.SSHHassh != "" {
			hassh = entry.SSHHassh
			break
		}
	}
	if hassh == "" {
		t.Fatal("expected ssh.client.hash.hassh to be set for SSH connection")
	}
	if len(hassh) != 32 {
		t.Errorf("expected ssh.client.hash.hassh to be 32-char hex, got %q", hassh)
	}
	t.Logf("real ssh client produced hassh: %s", hassh)
}

func TestLoomShipper(t *testing.T) {
	var received [][]map[string]interface{}
	var mu sync.Mutex
	srv := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodPost {
				t.Errorf("loom server: unexpected method %s", r.Method)
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			var batch []map[string]interface{}
			if err := json.NewDecoder(r.Body).Decode(&batch); err != nil {
				t.Errorf("loom server: decode: %v", err)
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			mu.Lock()
			received = append(received, batch)
			mu.Unlock()
			w.WriteHeader(http.StatusOK)
		}),
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("loom listen: %v", err)
	}
	go srv.Serve(ln)
	defer ln.Close()

	loomURL := "http://" + ln.Addr().String()

	cmd := exec.Command("go", "build", "-o", filepath.Join("..", "..", "spip-agent"), filepath.Join("..", "..", "cmd", "spip-agent"))
	if err := cmd.Run(); err != nil {
		t.Fatalf("build spip-agent: %v", err)
	}
	if err := setupIptables(t); err != nil {
		t.Fatalf("setup iptables: %v", err)
	}
	defer cleanupIptables(t)

	configPath := createTestConfigWithLoom(t, false, "", "", loomURL)
	defer os.RemoveAll(filepath.Dir(configPath))

	process, stdout, stdoutPipe := startSpip(t, configPath)
	defer func() {
		stopSpip(t, process)
		if stdoutPipe != nil {
			stdoutPipe.Close()
		}
	}()

	payload := []byte("Loom E2E payload")
	response, err := makeTCPRequest(t, false, payload)
	if err != nil {
		t.Fatalf("TCP request: %v", err)
	}
	if !bytes.Equal(response, []byte(testHost)) {
		t.Errorf("response: got %q, want %q", string(response), testHost)
	}

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		mu.Lock()
		n := len(received)
		mu.Unlock()
		if n > 0 {
			break
		}
		time.Sleep(200 * time.Millisecond)
	}

	mu.Lock()
	batches := received
	mu.Unlock()

	if len(batches) == 0 {
		t.Fatalf("loom server received no batches (stdout snippet: %s)", string(stdout.Bytes()[:min(500, stdout.Len())]))
	}
	var found bool
	for _, batch := range batches {
		for _, ev := range batch {
			src, _ := ev["source"].(map[string]interface{})
			if src != nil && src["ip"] == testHost {
				if ev["event"] != nil {
					found = true
					// Fingerprinting: Loom receives same ECS including network.community_id
					if netObj, ok := ev["network"].(map[string]interface{}); ok {
						if cid, ok := netObj["community_id"].(string); !ok || cid == "" {
							t.Errorf("expected Loom event to have network.community_id, got %v", netObj)
						}
					} else {
						t.Error("expected Loom event to have network object")
					}
					break
				}
			}
		}
		if found {
			break
		}
	}
	if !found {
		t.Errorf("no ECS event with source.ip=%s in received batches: %+v", testHost, batches)
	}
}

func TestConcurrentConnections(t *testing.T) {
	env := setupTestEnv(t, true)
	defer env.cleanup()

	// Test concurrent TCP and TLS connections
	const numConnections = 10
	errChan := make(chan error, numConnections*2)
	doneChan := make(chan struct{})

	expectedResponse := []byte(testHost)

	// Start TCP connections
	for i := 0; i < numConnections; i++ {
		go func(id int) {
			payload := []byte(fmt.Sprintf("TCP request %d", id))
			response, err := makeTCPRequest(t, false, payload)
			if err != nil {
				errChan <- fmt.Errorf("TCP request %d failed: %v", id, err)
				return
			}
			// Under load the server may send multiple responses (partial reads); accept any response that starts with the IP
			if !bytes.HasPrefix(response, expectedResponse) {
				errChan <- fmt.Errorf("TCP request %d: got %q, want prefix %q", id, string(response), string(expectedResponse))
				return
			}
			errChan <- nil
		}(i)
	}

	// Start TLS connections
	for i := 0; i < numConnections; i++ {
		go func(id int) {
			payload := []byte(fmt.Sprintf("TLS request %d", id))
			response, err := makeTCPRequest(t, true, payload)
			if err != nil {
				errChan <- fmt.Errorf("TLS request %d failed: %v", id, err)
				return
			}
			if !bytes.HasPrefix(response, expectedResponse) {
				errChan <- fmt.Errorf("TLS request %d: got %q, want prefix %q", id, string(response), string(expectedResponse))
				return
			}
			errChan <- nil
		}(i)
	}

	// Wait for all connections to complete
	go func() {
		for i := 0; i < numConnections*2; i++ {
			if err := <-errChan; err != nil {
				t.Error(err)
			}
		}
		close(doneChan)
	}()

	select {
	case <-doneChan:
		// All connections completed successfully
	case <-time.After(5 * time.Second):
		t.Fatal("Timeout waiting for concurrent connections")
	}
}

func TestLongRunningConnection(t *testing.T) {
	env := setupTestEnv(t, true)
	defer env.cleanup()

	expectedResponse := []byte(testHost)

	// Create a long-running connection
	conn, err := tls.Dial("tcp", fmt.Sprintf("%s:%d", testHost, testPort), &tls.Config{
		InsecureSkipVerify: true,
	})
	if err != nil {
		t.Fatalf("Failed to create long-running connection: %v", err)
	}
	defer conn.Close()

	// Send multiple messages over the same connection
	for i := 0; i < 5; i++ {
		payload := []byte(fmt.Sprintf("Message %d", i))
		if _, err := conn.Write(payload); err != nil {
			t.Fatalf("Failed to write message %d: %v", i, err)
		}

		response := make([]byte, len(expectedResponse))
		if _, err := io.ReadFull(conn, response); err != nil {
			t.Fatalf("Failed to read response for message %d: %v", i, err)
		}

		if !bytes.Equal(response, expectedResponse) {
			t.Errorf("Message %d: got %q, want %q", i, string(response), string(expectedResponse))
		}

		time.Sleep(100 * time.Millisecond)
	}
}

func TestConnectionReset(t *testing.T) {
	env := setupTestEnv(t, true)
	defer env.cleanup()

	// Test connection reset handling
	conn, err := net.Dial("tcp", net.JoinHostPort(testHost, fmt.Sprintf("%d", testPort)))
	if err != nil {
		t.Fatalf("Failed to create connection: %v", err)
	}

	// Send partial data and close immediately
	conn.Write([]byte("Partial"))
	conn.Close()

	// Wait a bit and try a new connection
	time.Sleep(100 * time.Millisecond)

	payload := []byte("New connection")
	response, err := makeTCPRequest(t, false, payload)
	if err != nil {
		t.Fatalf("Failed to make request after reset: %v", err)
	}

	expectedResponse := []byte(testHost)
	if !bytes.Equal(response, expectedResponse) {
		t.Errorf("After reset: got %q, want %q", string(response), string(expectedResponse))
	}
}

func TestProcessRestart(t *testing.T) {
	env := setupTestEnv(t, true)

	// Make initial request
	payload := []byte("Before restart")
	response, err := makeTCPRequest(t, true, payload)
	if err != nil {
		t.Fatalf("Failed to make request before restart: %v", err)
	}

	expectedResponse := []byte(testHost)
	if !bytes.Equal(response, expectedResponse) {
		t.Errorf("Before restart: got %q, want %q", string(response), string(expectedResponse))
	}

	// Stop the process
	stopSpip(t, env.spipProcess)
	env.spipProcess = nil

	// Start a new process
	var stdout *bytes.Buffer
	env.spipProcess, stdout, env.stdoutPipe = startSpip(t, env.configPath)
	env.stdout = stdout

	// Wait for the new process to start
	time.Sleep(2 * time.Second)

	// Make another request
	payload = []byte("After restart")
	response, err = makeTCPRequest(t, true, payload)
	if err != nil {
		t.Fatalf("Failed to make request after restart: %v", err)
	}

	if !bytes.Equal(response, expectedResponse) {
		t.Errorf("After restart: got %q, want %q", string(response), string(expectedResponse))
	}

	env.cleanup()
}

func TestOriginalDestinationPreservationTCP(t *testing.T) {
	env := setupTestEnv(t, false)
	defer env.cleanup()

	// Setup iptables rules to redirect multiple ports
	ports := []int{22, 80, 443, 3306, 5432}
	for _, port := range ports {
		cmd := exec.Command("iptables", "-t", "nat", "-A", "OUTPUT",
			"-p", "tcp",
			"-d", testHost,
			"--dport", fmt.Sprintf("%d", port),
			"-j", "REDIRECT",
			"--to-port", fmt.Sprintf("%d", testPort))
		if err := cmd.Run(); err != nil {
			t.Fatalf("Failed to add iptables rule for port %d: %v", port, err)
		}
	}

	// Test connections to different ports
	type testConn struct {
		port    int
		payload string
	}

	testCases := make([]testConn, len(ports))
	for i, port := range ports {
		testCases[i] = testConn{
			port:    port,
			payload: fmt.Sprintf("Test TCP connection to port %d", port),
		}
	}

	// Track which ports we've found with correct data
	foundPorts := make(map[int]bool)
	portPayloads := make(map[int]string)
	portSessions := make(map[int]string)

	expectedResponse := []byte(testHost)

	// Make connections and track session IDs
	for _, tc := range testCases {
		conn, err := net.Dial("tcp", net.JoinHostPort(testHost, fmt.Sprintf("%d", tc.port)))
		if err != nil {
			t.Fatalf("Failed to connect to port %d: %v", tc.port, err)
		}

		if _, err := conn.Write([]byte(tc.payload)); err != nil {
			t.Fatalf("Failed to write to port %d: %v", tc.port, err)
		}

		// Read response
		response := make([]byte, len(expectedResponse))
		if _, err := io.ReadFull(conn, response); err != nil {
			t.Fatalf("Failed to read from port %d: %v", tc.port, err)
		}

		if !bytes.Equal(response, expectedResponse) {
			t.Errorf("Port %d: response mismatch, got %q, want %q", tc.port, string(response), string(expectedResponse))
		}

		conn.Close()
	}

	// Wait for output to be written
	time.Sleep(time.Second)

	// Read and verify the JSON output
	output := env.getStdout()
	lines := strings.Split(output, "\n")

	// Verify each port appears in the output with correct original destination
	for _, line := range lines {
		if line == "" {
			continue
		}

		entry, err := ParseLogLine(line)
		if err != nil {
			t.Errorf("Failed to parse JSON line %q: %v", line, err)
			continue
		}

		// Look for connection entries that match our test cases
		if entry.DestinationPort != 0 {
			// Verify this was one of our test ports
			for _, tc := range testCases {
				if entry.DestinationPort == tc.port {
					// Verify all fields for this connection
					if entry.Payload != tc.payload {
						t.Errorf("Port %d: payload mismatch: got %q, want %q", tc.port, entry.Payload, tc.payload)
					}
					if entry.SourceIP != testHost {
						t.Errorf("Port %d: source IP mismatch: got %q, want %q", tc.port, entry.SourceIP, testHost)
					}
					if entry.DestinationIP != testHost {
						t.Errorf("Port %d: destination IP mismatch: got %q, want %q", tc.port, entry.DestinationIP, testHost)
					}
					if entry.IsTLS {
						t.Errorf("Port %d: connection incorrectly marked as TLS", tc.port)
					}
					if entry.SessionID == "" {
						t.Errorf("Port %d: missing session ID", tc.port)
					}
					foundPorts[tc.port] = true
					portPayloads[tc.port] = entry.Payload
					portSessions[tc.port] = entry.SessionID
				}
			}
		}
	}

	// Verify we found all ports with correct data
	for _, tc := range testCases {
		if !foundPorts[tc.port] {
			t.Errorf("Did not find connection to original port %d in output", tc.port)
		}
		if payload := portPayloads[tc.port]; payload != tc.payload {
			t.Errorf("Port %d: final payload mismatch: got %q, want %q", tc.port, payload, tc.payload)
		}
		if session := portSessions[tc.port]; session == "" {
			t.Errorf("Port %d: missing session ID in final verification", tc.port)
		}
	}
}

func TestOriginalDestinationPreservationTLS(t *testing.T) {
	env := setupTestEnv(t, true)
	defer env.cleanup()

	// Setup iptables rules to redirect multiple ports
	ports := []int{443, 8443, 9443} // Common HTTPS ports
	for _, port := range ports {
		cmd := exec.Command("iptables", "-t", "nat", "-A", "OUTPUT",
			"-p", "tcp",
			"-d", testHost,
			"--dport", fmt.Sprintf("%d", port),
			"-j", "REDIRECT",
			"--to-port", fmt.Sprintf("%d", testPort))
		if err := cmd.Run(); err != nil {
			t.Fatalf("Failed to add iptables rule for port %d: %v", port, err)
		}
	}

	// Test connections to different ports
	type testConn struct {
		port    int
		payload string
	}

	testCases := make([]testConn, len(ports))
	for i, port := range ports {
		testCases[i] = testConn{
			port:    port,
			payload: fmt.Sprintf("Test TLS connection to port %d", port),
		}
	}

	// Track which ports we've found with correct data
	foundPorts := make(map[int]bool)
	portPayloads := make(map[int]string)
	portSessions := make(map[int]string)

	expectedResponse := []byte(testHost)

	// Make connections and track session IDs
	var wg sync.WaitGroup
	for _, tc := range testCases {
		wg.Add(1)
		go func(tc testConn) {
			defer wg.Done()

			// Configure TLS client to skip all verification
			tlsConfig := &tls.Config{
				InsecureSkipVerify: true,
			}

			// Connect using TLS
			conn, err := tls.Dial("tcp", fmt.Sprintf("%s:%d", testHost, tc.port), tlsConfig)
			if err != nil {
				t.Errorf("Failed to connect to port %d: %v", tc.port, err)
				return
			}
			defer conn.Close()

			if _, err := conn.Write([]byte(tc.payload)); err != nil {
				t.Errorf("Failed to write to port %d: %v", tc.port, err)
				return
			}

			// Read response
			response := make([]byte, len(expectedResponse))
			if _, err := io.ReadFull(conn, response); err != nil {
				t.Errorf("Failed to read from port %d: %v", tc.port, err)
				return
			}

			if !bytes.Equal(response, expectedResponse) {
				t.Errorf("Port %d: response mismatch, got %q, want %q", tc.port, string(response), string(expectedResponse))
			}
		}(tc)
	}

	// Wait for all connections with a timeout
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		// All connections completed successfully
	case <-time.After(10 * time.Second):
		t.Fatal("Timeout waiting for connections")
	}

	// Wait for output to be written
	time.Sleep(time.Second)

	// Read and verify the JSON output
	output := env.getStdout()
	lines := strings.Split(output, "\n")

	// Verify each port appears in the output with correct original destination
	for _, line := range lines {
		if line == "" {
			continue
		}

		entry, err := ParseLogLine(line)
		if err != nil {
			t.Errorf("Failed to parse JSON line %q: %v", line, err)
			continue
		}

		// Look for connection entries that match our test cases
		if entry.DestinationPort != 0 {
			// Verify this was one of our test ports
			for _, tc := range testCases {
				if entry.DestinationPort == tc.port {
					// Verify all fields for this connection
					if entry.Payload != tc.payload {
						t.Errorf("Port %d: payload mismatch: got %q, want %q", tc.port, entry.Payload, tc.payload)
					}
					if entry.SourceIP != testHost {
						t.Errorf("Port %d: source IP mismatch: got %q, want %q", tc.port, entry.SourceIP, testHost)
					}
					if entry.DestinationIP != testHost {
						t.Errorf("Port %d: destination IP mismatch: got %q, want %q", tc.port, entry.DestinationIP, testHost)
					}
					if !entry.IsTLS {
						t.Errorf("Port %d: connection not marked as TLS", tc.port)
					}
					if entry.SessionID == "" {
						t.Errorf("Port %d: missing session ID", tc.port)
					}
					foundPorts[tc.port] = true
					portPayloads[tc.port] = entry.Payload
					portSessions[tc.port] = entry.SessionID
				}
			}
		}
	}

	// Verify we found all ports with correct data
	for _, tc := range testCases {
		if !foundPorts[tc.port] {
			t.Errorf("Did not find connection to original port %d in output", tc.port)
		}
		if payload := portPayloads[tc.port]; payload != tc.payload {
			t.Errorf("Port %d: final payload mismatch: got %q, want %q", tc.port, payload, tc.payload)
		}
		if session := portSessions[tc.port]; session == "" {
			t.Errorf("Port %d: missing session ID in final verification", tc.port)
		}
	}
}

func TestHighLoadConcurrent(t *testing.T) {
	env := setupTestEnv(t, true)
	defer env.cleanup()

	// Test parameters - reduced load for test environments
	const (
		totalDuration = 15 * time.Second // Increased timeout
		ratePerSecond = 4                // 4 connections per second
		totalConns    = 20               // Total connections to make
	)

	// Create channels for error reporting and completion signaling
	errChan := make(chan error, totalConns*2) // For both TCP and TLS
	doneChan := make(chan struct{})

	// Start connection maker at regular intervals
	ticker := time.NewTicker(time.Second / time.Duration(ratePerSecond))
	defer ticker.Stop()

	connCount := 0
	start := time.Now()

	expectedResponse := []byte(testHost)

	for connCount < totalConns {
		<-ticker.C

		// TCP goroutine
		go func(id int) {
			payload := []byte(fmt.Sprintf("TCP probe %d", id))
			response, err := makeTCPRequest(t, false, payload)
			if err != nil {
				errChan <- fmt.Errorf("TCP probe %d failed: %v", id, err)
				return
			}
			if !bytes.HasPrefix(response, expectedResponse) {
				errChan <- fmt.Errorf("TCP probe %d: response mismatch, got %q, want prefix %q", id, string(response), string(expectedResponse))
			}
			errChan <- nil
		}(connCount)

		// TLS goroutine
		go func(id int) {
			payload := []byte(fmt.Sprintf("TLS probe %d", id))
			response, err := makeTCPRequest(t, true, payload)
			if err != nil {
				errChan <- fmt.Errorf("TLS probe %d failed: %v", id, err)
				return
			}
			if !bytes.HasPrefix(response, expectedResponse) {
				errChan <- fmt.Errorf("TLS probe %d: response mismatch, got %q, want prefix %q", id, string(response), string(expectedResponse))
			}
			errChan <- nil
		}(connCount)

		connCount++
	}

	// Start error collector
	go func() {
		for i := 0; i < totalConns*2; i++ {
			if err := <-errChan; err != nil {
				t.Error(err)
			}
		}
		close(doneChan)
	}()

	// Wait for all connections to complete
	select {
	case <-doneChan:
		duration := time.Since(start)
		t.Logf("Completed %d connections in %v (rate: %.2f/sec)",
			totalConns*2, duration, float64(totalConns*2)/duration.Seconds())
	case <-time.After(totalDuration):
		t.Fatal("Test timed out")
	}
}
