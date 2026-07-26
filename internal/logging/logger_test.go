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

// TestLogConnection_Fingerprinting verifies ECS fingerprint fields: network.community_id, tls.client.*, http.request.hash.ja4h, ssh.client.hash.hassh.
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
		HTTPJA4H:              "ge11n00100_53b50f4ec784",
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

	// http.request.hash.ja4h is derived from payload in logger; assert present for HTTP-like payload
	if httpObj, ok := logged["http"].(map[string]interface{}); ok {
		if req, ok := httpObj["request"].(map[string]interface{}); ok {
			if hash, ok := req["hash"].(map[string]interface{}); ok {
				if ja4h, _ := hash["ja4h"].(string); ja4h == "" {
					t.Error("http.request.hash.ja4h should be set for HTTP-like payload")
				}
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

func TestLogConnection_UDPTransport(t *testing.T) {
	tmpFile, err := os.CreateTemp("", "spip-udp-log-test")
	if err != nil {
		t.Fatalf("create temp file: %v", err)
	}
	defer os.Remove(tmpFile.Name())
	defer tmpFile.Close()

	logger := NewLogger(tmpFile)
	connData := &ConnectionData{
		Timestamp:       time.Now().Unix(),
		Payload:         "udp payload",
		PayloadHex:      "756470207061796c6f6164",
		SourceIP:        "192.0.2.10",
		SourcePort:      53000,
		DestinationIP:   "198.51.100.20",
		DestinationPort: 53,
		SessionID:       "udp-session",
		Transport:       "udp",
		CommunityID:     "1:udp",
		BytesIn:         11,
		RecordSeq:       1,
	}

	if err := logger.LogConnection(connData); err != nil {
		t.Fatalf("LogConnection: %v", err)
	}
	if _, err := tmpFile.Seek(0, 0); err != nil {
		t.Fatalf("seek: %v", err)
	}

	var logged map[string]interface{}
	if err := json.NewDecoder(tmpFile).Decode(&logged); err != nil {
		t.Fatalf("decode: %v", err)
	}
	network, ok := logged["network"].(map[string]interface{})
	if !ok {
		t.Fatal("missing network object")
	}
	if transport, _ := network["transport"].(string); transport != "udp" {
		t.Fatalf("network.transport = %q, want udp", transport)
	}
	if protocol, ok := network["protocol"]; ok {
		t.Fatalf("network.protocol unexpectedly set for UDP: %v", protocol)
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
