package logging

import (
	"bytes"
	"encoding/json"
	"io"
	"os"
	"testing"
	"time"
)

func TestLogMessage(t *testing.T) {
	// Create a temporary file for testing
	tmpFile, err := os.CreateTemp("", "spip-log-test")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	defer os.Remove(tmpFile.Name())
	defer tmpFile.Close()

	logger := NewLogger(tmpFile)

	// Test each log level
	tests := []struct {
		level   LogLevel
		target  string
		message string
	}{
		{LevelDebug, "test", "debug message"},
		{LevelInfo, "test", "info message"},
		{LevelWarn, "test", "warning message"},
		{LevelError, "test", "error message"},
	}

	for _, tt := range tests {
		t.Run(string(tt.level), func(t *testing.T) {
			err := logger.Log(tt.level, tt.target, tt.message)
			if err != nil {
				t.Errorf("Log() error = %v", err)
				return
			}
		})
	}

	// Reset file pointer to beginning
	if _, err := tmpFile.Seek(0, 0); err != nil {
		t.Fatalf("Failed to seek file: %v", err)
	}

	// Read and verify log entries
	decoder := json.NewDecoder(tmpFile)
	for _, tt := range tests {
		var logMsg LogMessage
		if err := decoder.Decode(&logMsg); err != nil {
			t.Fatalf("Failed to decode log message: %v", err)
		}

		if logMsg.Level != tt.level {
			t.Errorf("Log level = %v, want %v", logMsg.Level, tt.level)
		}
		if logMsg.Target != tt.target {
			t.Errorf("Log target = %v, want %v", logMsg.Target, tt.target)
		}
		if logMsg.Message != tt.message {
			t.Errorf("Log message = %v, want %v", logMsg.Message, tt.message)
		}
		if logMsg.RecordType != "log" {
			t.Errorf("Log record type = %v, want 'log'", logMsg.RecordType)
		}
	}
}

func TestLogConnection(t *testing.T) {
	// Create a temporary file for testing
	tmpFile, err := os.CreateTemp("", "spip-conn-test")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	defer os.Remove(tmpFile.Name())
	defer tmpFile.Close()

	logger := NewLogger(tmpFile)

	// Test connection data logging
	connData := &ConnectionData{
		Timestamp:       time.Now().Unix(),
		Payload:         "test payload",
		PayloadHex:      "74657374207061796c6f6164",
		SourceIP:        "127.0.0.1",
		SourcePort:      12345,
		DestinationIP:   "192.168.1.1",
		DestinationPort: 80,
		SessionID:       "test-session",
		IsTLS:           true,
	}

	if err := logger.LogConnection(connData); err != nil {
		t.Fatalf("LogConnection() error = %v", err)
	}

	// Reset file pointer to beginning
	if _, err := tmpFile.Seek(0, 0); err != nil {
		t.Fatalf("Failed to seek file: %v", err)
	}

	// Read and verify ECS-shaped connection data
	var logged map[string]interface{}
	decoder := json.NewDecoder(tmpFile)
	if err := decoder.Decode(&logged); err != nil {
		t.Fatalf("Failed to decode connection data: %v", err)
	}

	// Check event.id
	evt, ok := logged["event"].(map[string]interface{})
	if !ok {
		t.Fatalf("missing event object in logged record")
	}
	if id, _ := evt["id"].(string); id != connData.SessionID {
		t.Errorf("event.id = %v, want %v", id, connData.SessionID)
	}

	// Check source
	src, ok := logged["source"].(map[string]interface{})
	if !ok {
		t.Fatalf("missing source object in logged record")
	}
	if sip, _ := src["ip"].(string); sip != connData.SourceIP {
		t.Errorf("source.ip = %v, want %v", sip, connData.SourceIP)
	}
	if sport, _ := src["port"].(float64); uint16(sport) != connData.SourcePort {
		t.Errorf("source.port = %v, want %v", sport, connData.SourcePort)
	}

	// Check destination
	dst, ok := logged["destination"].(map[string]interface{})
	if !ok {
		t.Fatalf("missing destination object in logged record")
	}
	if dip, _ := dst["ip"].(string); dip != connData.DestinationIP {
		t.Errorf("destination.ip = %v, want %v", dip, connData.DestinationIP)
	}
	if dport, _ := dst["port"].(float64); uint16(dport) != connData.DestinationPort {
		t.Errorf("destination.port = %v, want %v", dport, connData.DestinationPort)
	}

	// Check network.protocol derived from IsTLS
	if netObj, ok := logged["network"].(map[string]interface{}); ok {
		if connData.IsTLS {
			if proto, _ := netObj["protocol"].(string); proto != "tls" {
				t.Errorf("network.protocol = %v, want %v", proto, "tls")
			}
		}
	} else {
		t.Fatalf("missing network object in logged record")
	}

	// Payload should be available under event.summary (non-HTTP) or http.request.body (HTTP), fallback to top-level payload
	var gotPayload string
	if ev, ok := logged["event"].(map[string]interface{}); ok {
		if summary, _ := ev["summary"].(string); summary != "" {
			gotPayload = summary
		}
	}
	if gotPayload == "" {
		if httpObj, ok := logged["http"].(map[string]interface{}); ok {
			if req, ok := httpObj["request"].(map[string]interface{}); ok {
				if body, _ := req["body"].(string); body != "" {
					gotPayload = body
				}
			}
		}
	}
	if gotPayload == "" {
		if p, _ := logged["payload"].(string); p != "" {
			gotPayload = p
		}
	}
	if gotPayload != connData.Payload {
		t.Errorf("payload = %v, want %v", gotPayload, connData.Payload)
	}

	// Payload hex should be under event.original_payload_hex (ECS) or fallback to payload_hex
	var gotPayloadHex string
	if ev, ok := logged["event"].(map[string]interface{}); ok {
		if oph, _ := ev["original_payload_hex"].(string); oph != "" {
			gotPayloadHex = oph
		}
	}
	if gotPayloadHex == "" {
		if ph, _ := logged["payload_hex"].(string); ph != "" {
			gotPayloadHex = ph
		}
	}
	if gotPayloadHex != connData.PayloadHex {
		t.Errorf("payload_hex/event.original_payload_hex = %v, want %v", gotPayloadHex, connData.PayloadHex)
	}

	// observer / host name (if set) should match
	if obs, ok := logged["observer"].(map[string]interface{}); ok {
		if hn, _ := obs["hostname"].(string); hn == "" {
			t.Errorf("observer.hostname is empty, expected value")
		}
	}
}

// TestLogConnection_Fingerprinting verifies ECS fingerprint fields: network.community_id, tls.client.*, ssh.client.hash.hassh.
func TestLogConnection_Fingerprinting(t *testing.T) {
	tmpFile, err := os.CreateTemp("", "spip-fp-test")
	if err != nil {
		t.Fatalf("create temp file: %v", err)
	}
	defer os.Remove(tmpFile.Name())
	defer tmpFile.Close()

	logger := NewLogger(tmpFile)
	connData := &ConnectionData{
		Timestamp:             time.Now().Unix(),
		Payload:               "GET / HTTP/1.1\r\nHost: x\r\n\r\n",
		PayloadHex:            "474554202f20485454502f312e310d0a486f73743a20780d0a0d0a",
		SourceIP:              "10.0.0.1",
		SourcePort:            40000,
		DestinationIP:         "10.0.0.2",
		DestinationPort:       443,
		SessionID:             "fp-session",
		IsTLS:                 true,
		TLSServerName:         "example.com",
		TLSALPN:               "h2",
		CommunityID:           "1:abc123",
		TLSSupportedProtocols: []string{"h2", "http/1.1"},
		TLSJA4:                "t13d1516h2_8daaf6152771_e5627efa2ab1",
		SSHHassh:              "92674389fa1e47a27ddd8d9b63ecd42b",
	}

	if err := logger.LogConnection(connData); err != nil {
		t.Fatalf("LogConnection: %v", err)
	}
	if _, err := tmpFile.Seek(0, 0); err != nil {
		t.Fatalf("Seek: %v", err)
	}

	var logged map[string]interface{}
	if err := json.NewDecoder(tmpFile).Decode(&logged); err != nil {
		t.Fatalf("decode: %v", err)
	}

	// network.community_id
	if netObj, ok := logged["network"].(map[string]interface{}); ok {
		if cid, _ := netObj["community_id"].(string); cid != connData.CommunityID {
			t.Errorf("network.community_id = %q, want %q", cid, connData.CommunityID)
		}
	} else {
		t.Fatal("missing network object")
	}

	// tls.client.server_name, tls.client.supported_protocols, tls.client.hash.ja4
	if tlsObj, ok := logged["tls"].(map[string]interface{}); ok {
		client, _ := tlsObj["client"].(map[string]interface{})
		if client == nil {
			t.Fatal("missing tls.client")
		}
		if sn, _ := client["server_name"].(string); sn != connData.TLSServerName {
			t.Errorf("tls.client.server_name = %q, want %q", sn, connData.TLSServerName)
		}
		if protos, ok := client["supported_protocols"].([]interface{}); ok {
			if len(protos) != len(connData.TLSSupportedProtocols) {
				t.Errorf("tls.client.supported_protocols len = %d, want %d", len(protos), len(connData.TLSSupportedProtocols))
			}
		}
		if hash, ok := client["hash"].(map[string]interface{}); ok {
			if ja4, _ := hash["ja4"].(string); ja4 != connData.TLSJA4 {
				t.Errorf("tls.client.hash.ja4 = %q, want %q", ja4, connData.TLSJA4)
			}
		} else {
			t.Error("missing tls.client.hash")
		}
	} else {
		t.Fatal("missing tls object")
	}

	// http.request carries no hash field.
	if httpObj, ok := logged["http"].(map[string]interface{}); ok {
		if req, ok := httpObj["request"].(map[string]interface{}); ok {
			if _, ok := req["hash"]; ok {
				t.Error("http.request.hash should not be emitted")
			}
		}
	}

	// ssh.client.hash.hassh
	if sshObj, ok := logged["ssh"].(map[string]interface{}); ok {
		client, _ := sshObj["client"].(map[string]interface{})
		if client == nil {
			t.Fatal("missing ssh.client")
		}
		if hash, ok := client["hash"].(map[string]interface{}); ok {
			if hassh, _ := hash["hassh"].(string); hassh != connData.SSHHassh {
				t.Errorf("ssh.client.hash.hassh = %q, want %q", hassh, connData.SSHHassh)
			}
		} else {
			t.Error("missing ssh.client.hash")
		}
	} else {
		t.Fatal("missing ssh object")
	}
}

// TestLogConnection_LoomReceivesSameECS verifies that when ecsChan is set (Loom path), the same ECS record is sent.
func TestLogConnection_LoomReceivesSameECS(t *testing.T) {
	ecsChan := make(chan map[string]interface{}, 1)
	logger := NewLoggerWithECSChannel(io.Discard, ecsChan)

	connData := &ConnectionData{
		Timestamp:       time.Now().Unix(),
		Payload:         "test",
		PayloadHex:      "74657374",
		SourceIP:        "127.0.0.1",
		SourcePort:      1,
		DestinationIP:   "192.168.1.1",
		DestinationPort: 80,
		SessionID:       "loom-session",
		IsTLS:           false,
		CommunityID:     "1:xyz",
	}

	if err := logger.LogConnection(connData); err != nil {
		t.Fatalf("LogConnection: %v", err)
	}

	select {
	case m := <-ecsChan:
		if m["event"] == nil || m["source"] == nil || m["destination"] == nil || m["network"] == nil {
			t.Errorf("Loom received ECS missing core keys: %v", m)
		}
		if netObj, ok := m["network"].(map[string]interface{}); ok {
			if cid, _ := netObj["community_id"].(string); cid != connData.CommunityID {
				t.Errorf("Loom network.community_id = %q, want %q", cid, connData.CommunityID)
			}
		}
	case <-time.After(time.Second):
		t.Fatal("Loom ecsChan did not receive record")
	}
}

func TestLoggerHelperFunctions(t *testing.T) {
	var buf bytes.Buffer
	logger := NewLogger(&buf)

	tests := []struct {
		name    string
		logFunc func(string, string)
		level   LogLevel
		target  string
		message string
	}{
		{"Debug", logger.Debug, LevelDebug, "test", "debug message"},
		{"Info", logger.Info, LevelInfo, "test", "info message"},
		{"Warn", logger.Warn, LevelWarn, "test", "warning message"},
		{"Error", logger.Error, LevelError, "test", "error message"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			buf.Reset()
			tt.logFunc(tt.target, tt.message)

			var logMsg LogMessage
			if err := json.NewDecoder(&buf).Decode(&logMsg); err != nil {
				t.Fatalf("Failed to decode log message: %v", err)
			}

			if logMsg.Level != tt.level {
				t.Errorf("Log level = %v, want %v", logMsg.Level, tt.level)
			}
			if logMsg.Target != tt.target {
				t.Errorf("Log target = %v, want %v", logMsg.Target, tt.target)
			}
			if logMsg.Message != tt.message {
				t.Errorf("Log message = %v, want %v", logMsg.Message, tt.message)
			}
		})
	}
}

// TestLogConnection_BehavioralAndJA3 verifies the Phase 1 ECS additions:
// tls.client.ja3, event.sequence, event.duration (ns), source.bytes,
// destination.bytes, network.bytes.
func TestLogConnection_BehavioralAndJA3(t *testing.T) {
	tmpFile, err := os.CreateTemp("", "spip-beh-test")
	if err != nil {
		t.Fatalf("create temp file: %v", err)
	}
	defer os.Remove(tmpFile.Name())
	defer tmpFile.Close()

	logger := NewLogger(tmpFile)
	connData := &ConnectionData{
		Timestamp:       time.Now().Unix(),
		Payload:         "USER root\r\n",
		SourceIP:        "10.0.0.1",
		SourcePort:      40000,
		DestinationIP:   "10.0.0.2",
		DestinationPort: 21,
		SessionID:       "beh-session",
		IsTLS:           true,
		TLSJA3:          "769,47-53,0-23-65281,29-23-24,0",
		DurationMs:      1500,
		BytesIn:         42,
		BytesOut:        100,
		RecordSeq:       3,
	}
	if err := logger.LogConnection(connData); err != nil {
		t.Fatalf("LogConnection: %v", err)
	}
	if _, err := tmpFile.Seek(0, 0); err != nil {
		t.Fatalf("Seek: %v", err)
	}
	var logged map[string]interface{}
	if err := json.NewDecoder(tmpFile).Decode(&logged); err != nil {
		t.Fatalf("decode: %v", err)
	}

	// tls.client.ja3
	tlsObj, _ := logged["tls"].(map[string]interface{})
	client, _ := tlsObj["client"].(map[string]interface{})
	if client == nil {
		t.Fatal("missing tls.client")
	}
	if ja3, _ := client["ja3"].(string); ja3 != connData.TLSJA3 {
		t.Errorf("tls.client.ja3 = %q, want %q", ja3, connData.TLSJA3)
	}

	// event.sequence + event.duration (ns)
	event, _ := logged["event"].(map[string]interface{})
	if seq, _ := event["sequence"].(float64); int(seq) != connData.RecordSeq {
		t.Errorf("event.sequence = %v, want %d", event["sequence"], connData.RecordSeq)
	}
	if dur, _ := event["duration"].(float64); int64(dur) != connData.DurationMs*1_000_000 {
		t.Errorf("event.duration = %v ns, want %d", event["duration"], connData.DurationMs*1_000_000)
	}

	// source.bytes / destination.bytes / network.bytes
	if src, _ := logged["source"].(map[string]interface{}); int64(src["bytes"].(float64)) != connData.BytesIn {
		t.Errorf("source.bytes = %v, want %d", logged["source"], connData.BytesIn)
	}
	if dst, _ := logged["destination"].(map[string]interface{}); int64(dst["bytes"].(float64)) != connData.BytesOut {
		t.Errorf("destination.bytes = %v, want %d", logged["destination"], connData.BytesOut)
	}
	if net, _ := logged["network"].(map[string]interface{}); int64(net["bytes"].(float64)) != connData.BytesIn+connData.BytesOut {
		t.Errorf("network.bytes = %v, want %d", logged["network"], connData.BytesIn+connData.BytesOut)
	}
}

// TestLogConnection_HostHeaderIPv6 pins how the Host header is split into
// url.domain and url.port.
//
// The split used to be strings.LastIndex(host, ":"), which is correct for
// "example.com:80" and wrong for every bracket-less IPv6 literal: it cut at the
// final colon of the address itself, so "2a0f:85c1:b73:383::a" was recorded as
// "2a0f:85c1:b73:383:". That silently corrupted url.domain, and downstream the
// truncated form no longer matched the sensor-address redaction applied to the
// public dataset, so a partial sensor address reached a published column.
//
// net.SplitHostPort knows the bracket rules; the fallback strips brackets for a
// bracketed address carrying no port.
func TestLogConnection_HostHeaderIPv6(t *testing.T) {
	cases := []struct {
		name       string
		hostHeader string
		wantDomain string
		wantPort   int
	}{
		{"name only", "example.com", "example.com", 0},
		{"name and port", "example.com:8080", "example.com", 8080},
		{"ipv4", "1.2.3.4", "1.2.3.4", 0},
		{"ipv4 and port", "1.2.3.4:80", "1.2.3.4", 80},
		{"bare ipv6", "2a0f:85c1:b73:383::a", "2a0f:85c1:b73:383::a", 0},
		{"bracketed ipv6", "[2a0f:85c1:b73:383::a]", "2a0f:85c1:b73:383::a", 0},
		{"bracketed ipv6 and port", "[2a0f:85c1:b73:383::a]:8080", "2a0f:85c1:b73:383::a", 8080},
		{"loopback ipv6", "::1", "::1", 0},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tmpFile, err := os.CreateTemp("", "spip-host-test")
			if err != nil {
				t.Fatalf("temp file: %v", err)
			}
			defer os.Remove(tmpFile.Name())
			defer tmpFile.Close()

			logger := NewLogger(tmpFile)
			payload := "GET /probe HTTP/1.1\r\nHost: " + tc.hostHeader + "\r\n\r\n"
			if err := logger.LogConnection(&ConnectionData{
				Timestamp:       time.Now().Unix(),
				Payload:         payload,
				SourceIP:        "127.0.0.1",
				SourcePort:      12345,
				DestinationIP:   "192.168.1.1",
				DestinationPort: 80,
				SessionID:       "host-header-test",
			}); err != nil {
				t.Fatalf("LogConnection: %v", err)
			}

			if _, err := tmpFile.Seek(0, 0); err != nil {
				t.Fatalf("seek: %v", err)
			}
			var logged map[string]interface{}
			if err := json.NewDecoder(tmpFile).Decode(&logged); err != nil {
				t.Fatalf("decode: %v", err)
			}

			urlObj, ok := logged["url"].(map[string]interface{})
			if !ok {
				t.Fatalf("no url object in %v", logged)
			}
			if got, _ := urlObj["domain"].(string); got != tc.wantDomain {
				t.Errorf("url.domain = %q, want %q", got, tc.wantDomain)
			}
			gotPort := 0
			if p, ok := urlObj["port"].(float64); ok {
				gotPort = int(p)
			}
			if gotPort != tc.wantPort {
				t.Errorf("url.port = %d, want %d", gotPort, tc.wantPort)
			}
		})
	}
}
