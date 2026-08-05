package logging

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"regexp"
	"strconv"
	"strings"
	"time"

	"spip/internal/fingerprint"
)

// LogLevel represents the severity of a log message
type LogLevel string

const (
	LevelDebug LogLevel = "DEBUG"
	LevelInfo  LogLevel = "INFO"
	LevelWarn  LogLevel = "WARN"
	LevelError LogLevel = "ERROR"
)

// LogMessage represents a structured log message
type LogMessage struct {
	Timestamp  int64    `json:"timestamp"`
	Level      LogLevel `json:"level"`
	Message    string   `json:"message"`
	Target     string   `json:"target"`
	RecordType string   `json:"record_type"`
}

// ConnectionData represents TCP connection data
type ConnectionData struct {
	// Name of the agent that produced this record (optional)
	Name               string `json:"name,omitempty"`
	Timestamp          int64  `json:"timestamp"`
	Payload            string `json:"payload"`
	PayloadHex         string `json:"payload_hex"`
	SourceIP           string `json:"source_ip"`
	SourcePort         uint16 `json:"source_port"`
	DestinationIP      string `json:"destination_ip"`
	DestinationPort    uint16 `json:"destination_port"`
	SessionID          string `json:"session_id"`
	IsTLS              bool   `json:"is_tls"`
	TLSALPN            string `json:"tls_alpn,omitempty"`
	TLSServerName      string `json:"tls_server_name,omitempty"`
	TLSVersion         string `json:"tls_version,omitempty"`
	TLSCipherSuite     string `json:"tls_cipher_suite,omitempty"`
	TLSClientSubject   string `json:"tls_client_subject,omitempty"`
	TLSClientIssuer    string `json:"tls_client_issuer,omitempty"`
	TLSClientNotBefore int64  `json:"tls_client_not_before,omitempty"`
	TLSClientNotAfter  int64  `json:"tls_client_not_after,omitempty"`

	// Fingerprinting (ECS)
	CommunityID           string   `json:"community_id,omitempty"`            // network.community_id
	TLSSupportedProtocols []string `json:"tls_supported_protocols,omitempty"` // tls.client.supported_protocols (ALPN list from ClientHello)
	TLSJA4                string   `json:"tls_ja4,omitempty"`                 // tls.client.hash.ja4
	TLSJA3                string   `json:"tls_ja3,omitempty"`                 // tls.client.ja3 (legacy MD5 fingerprint)
	HTTPJA4H              string   `json:"http_ja4h,omitempty"`               // http.request.hash.ja4h
	SSHHassh              string   `json:"ssh_hassh,omitempty"`               // ssh.client.hash.hassh

	// Behavioral metadata (cumulative within the session up to this record)
	DurationMs int64 `json:"duration_ms,omitempty"` // event.duration (emitted in ns) since connect
	BytesIn    int64 `json:"bytes_in,omitempty"`    // source.bytes captured so far
	BytesOut   int64 `json:"bytes_out,omitempty"`   // destination.bytes sent so far
	RecordSeq  int   `json:"record_seq,omitempty"`  // event.sequence — this record's index in the session (1-based)
}

// Logger defines the interface for logging operations
type Logger interface {
	Log(level LogLevel, target, message string) error
	LogConnection(data *ConnectionData) error
	Debug(target, message string)
	Info(target, message string)
	Warn(target, message string)
	Error(target, message string)
}

type FileLogger struct {
	output  io.Writer
	ecsChan chan<- map[string]interface{}
}

var httpReqLineRe = regexp.MustCompile(`^(GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH)\s+(\S+)\s+(HTTP/1\.[01])$`)

func NewLogger(output io.Writer) Logger {
	return &FileLogger{output: output}
}

func NewLoggerWithECSChannel(output io.Writer, ecsChan chan<- map[string]interface{}) Logger {
	return &FileLogger{output: output, ecsChan: ecsChan}
}

// Log writes a log message in JSON format
func (l *FileLogger) Log(level LogLevel, target, message string) error {
	logMsg := LogMessage{
		Timestamp:  time.Now().Unix(),
		Level:      level,
		Message:    message,
		Target:     target,
		RecordType: "log",
	}

	return l.writeJSON(logMsg)
}

// LogConnection writes connection data in JSON format
func (l *FileLogger) LogConnection(data *ConnectionData) error {
	// Build an ECS-like record using only available data (no external lookups)
	ecs := make(map[string]interface{})

	// @timestamp in RFC3339 UTC
	ecs["@timestamp"] = time.Unix(data.Timestamp, 0).UTC().Format(time.RFC3339Nano)

	// event.id (shared across all records of a connection = the session key),
	// plus behavioral metadata: event.sequence and event.duration (nanoseconds).
	event := map[string]interface{}{
		"id": data.SessionID,
	}
	if data.RecordSeq > 0 {
		event["sequence"] = data.RecordSeq
	}
	if data.DurationMs > 0 {
		event["duration"] = data.DurationMs * 1_000_000 // ms -> ns per ECS
	}
	ecs["event"] = event

	// source and destination (+ per-session cumulative byte counts)
	source := map[string]interface{}{
		"ip":   data.SourceIP,
		"port": data.SourcePort,
	}
	if data.BytesIn > 0 {
		source["bytes"] = data.BytesIn
	}
	ecs["source"] = source
	destination := map[string]interface{}{
		"ip":   data.DestinationIP,
		"port": data.DestinationPort,
	}
	if data.BytesOut > 0 {
		destination["bytes"] = data.BytesOut
	}
	ecs["destination"] = destination

	// observer and host hostname from agent name, if present (ECS fields)
	if data.Name != "" {
		ecs["observer"] = map[string]interface{}{"hostname": data.Name, "id": data.Name} // observer.hostname + observer.id
		ecs["host"] = map[string]interface{}{"name": data.Name}                          // host.name
	}

	// network transport/protocol hints (derived from IsTLS) + Community ID
	network := map[string]interface{}{"transport": "tcp"}
	if data.CommunityID != "" {
		network["community_id"] = data.CommunityID
	}
	if data.IsTLS {
		network["protocol"] = "tls"
	}
	if data.BytesIn > 0 || data.BytesOut > 0 {
		network["bytes"] = data.BytesIn + data.BytesOut
	}
	ecs["network"] = network

	// ECS tls.client.* (server_name, supported_protocols, hash.ja4) + legacy fields
	if data.IsTLS {
		tlsClient := map[string]interface{}{}
		if data.TLSServerName != "" {
			tlsClient["server_name"] = data.TLSServerName
		}
		if len(data.TLSSupportedProtocols) > 0 {
			tlsClient["supported_protocols"] = data.TLSSupportedProtocols
		}
		if data.TLSJA4 != "" {
			tlsClient["hash"] = map[string]interface{}{"ja4": data.TLSJA4}
		}
		if data.TLSJA3 != "" {
			tlsClient["ja3"] = data.TLSJA3 // ECS tls.client.ja3 (legacy MD5 fingerprint)
		}
		if data.TLSVersion != "" {
			tlsClient["version"] = data.TLSVersion
		}
		if data.TLSCipherSuite != "" {
			tlsClient["cipher"] = data.TLSCipherSuite
		}
		clientCert := map[string]interface{}{}
		if data.TLSClientSubject != "" {
			clientCert["subject"] = data.TLSClientSubject
		}
		if data.TLSClientIssuer != "" {
			clientCert["issuer"] = data.TLSClientIssuer
		}
		if data.TLSClientNotBefore != 0 {
			clientCert["not_before"] = time.Unix(data.TLSClientNotBefore, 0).UTC().Format(time.RFC3339Nano)
		}
		if data.TLSClientNotAfter != 0 {
			clientCert["not_after"] = time.Unix(data.TLSClientNotAfter, 0).UTC().Format(time.RFC3339Nano)
		}
		if len(clientCert) > 0 {
			tlsClient["client_certificate"] = clientCert
		}
		if len(tlsClient) > 0 {
			tlsObj := map[string]interface{}{"client": tlsClient}
			if data.TLSALPN != "" {
				tlsObj["alpn"] = data.TLSALPN
			}
			ecs["tls"] = tlsObj
		}
	}

	// Attempt lightweight HTTP parsing from payload if it resembles an HTTP request.
	// Use a stricter check: require a valid request-line and either a header
	// terminator ("\r\n\r\n") or an explicit Host header. This reduces
	// false positives when processing arbitrary probes.
	payload := data.Payload
	if payload != "" {
		// Prepare http container
		httpObj := map[string]interface{}{}

		// Split into lines by CRLF
		lines := strings.Split(payload, "\r\n")

		if len(lines) > 0 {
			reqLine := lines[0]
			if m := httpReqLineRe.FindStringSubmatch(reqLine); m != nil {
				method := m[1]
				path := m[2]
				version := ""
				if len(m) > 3 {
					version = m[3]
				}

				// Check for header terminator or Host header presence
				hasTerminator := strings.Contains(payload, "\r\n\r\n")
				hasHost := false
				headers := map[string]string{}
				headerNamesInOrder := []string{}
				bodyStartIndex := -1

				// Walk lines after request-line to collect headers until blank line
				for _, ln := range lines[1:] {
					if ln == "" { // end of headers
						// Compute body start offset in original payload (if any)
						idx := strings.Index(payload, "\r\n\r\n")
						if idx != -1 && idx+4 <= len(payload) {
							bodyStartIndex = idx + 4
						}
						break
					}
					lower := strings.ToLower(ln)
					if strings.HasPrefix(lower, "host:") {
						hasHost = true
					}
					// Parse "Key: Value" style headers
					if idx := strings.Index(ln, ":"); idx > 0 {
						name := strings.TrimSpace(ln[:idx])
						value := strings.TrimSpace(ln[idx+1:])
						if name != "" {
							headers[strings.ToLower(name)] = value
							headerNamesInOrder = append(headerNamesInOrder, name)
						}
					}
				}

				// If ALPN indicates HTTP (e.g. http/1.1 or h2) we can be more permissive
				alpnIndicatesHTTP := false
				if data.IsTLS && (data.TLSALPN == "http/1.1" || data.TLSALPN == "h2" || data.TLSALPN == "h2-14") {
					alpnIndicatesHTTP = true
				}

				if hasTerminator || hasHost || alpnIndicatesHTTP {
					// Treat as HTTP
					reqObj := map[string]interface{}{"method": method}
					if len(headers) > 0 {
						reqObj["headers"] = headers
					}
					// JA4H: method, version, header order, cookie/referer/lang
					ja4h := fingerprint.JA4H(method, version, headerNamesInOrder,
						headers["cookie"] != "", headers["referer"] != "",
						headers["accept-language"])
					if ja4h != "" {
						reqObj["hash"] = map[string]interface{}{"ja4h": ja4h}
					}
					httpObj["request"] = reqObj

					// Build url.* from path and Host header when available
					urlObj := map[string]interface{}{"path": path}
					if hostHeader, ok := headers["host"]; ok && hostHeader != "" {
						// Split host:port if present
						host := hostHeader
						var portVal int
						if h, pStr, err := net.SplitHostPort(hostHeader); err == nil {
							host = h
							if p, err := strconv.Atoi(pStr); err == nil {
								portVal = p
							}
						} else {
							if strings.HasPrefix(host, "[") && strings.HasSuffix(host, "]") {
								host = host[1 : len(host)-1]
							}
						}
						if host != "" {
							urlObj["domain"] = host
						}
						if portVal != 0 {
							urlObj["port"] = portVal
						}
					}
					ecs["url"] = urlObj

					// Extract User-Agent if present (prefer parsed header)
					if ua, ok := headers["user-agent"]; ok && ua != "" {
						ecs["user_agent"] = map[string]interface{}{"original": ua}
					}

					// If there is a real body after headers, attach to http.request.body.content
					if hasTerminator && bodyStartIndex != -1 && bodyStartIndex < len(payload) {
						body := payload[bodyStartIndex:]
						if body != "" {
							bodyObj := map[string]interface{}{"content": body}
							// bytes length in UTF-8
							bodyObj["bytes"] = len([]byte(body))
							reqObj["body"] = bodyObj
						}
					}

					ecs["http"] = httpObj
				} else {
					// Looks like a request-line but missing headers/terminator => don't
					// classify as HTTP. Preserve payload in event.summary (keeping the
					// behavioral fields already set on the event map).
					if ev, ok := ecs["event"].(map[string]interface{}); ok {
						ev["summary"] = data.Payload
					}
				}
			} else {
				// Not an HTTP request-line: preserve payload in event.summary
				if ev, ok := ecs["event"].(map[string]interface{}); ok {
					ev["summary"] = data.Payload
				}
			}
		}
	}

	// SSH client fingerprint (Hassh) when present
	if data.SSHHassh != "" {
		ecs["ssh"] = map[string]interface{}{
			"client": map[string]interface{}{
				"hash": map[string]interface{}{"hassh": data.SSHHassh},
			},
		}
	}

	// place original payload hex under event.original_payload_hex (ECS extension)
	if data.PayloadHex != "" {
		// ensure event map exists
		if ev, ok := ecs["event"].(map[string]interface{}); ok {
			ev["original_payload_hex"] = data.PayloadHex
			ecs["event"] = ev
		} else {
			ecs["event"] = map[string]interface{}{"id": data.SessionID, "original_payload_hex": data.PayloadHex}
		}
	}

	if ev, ok := ecs["event"].(map[string]interface{}); ok {
		ev["ingested_by"] = "spip"
		ecs["event"] = ev
	} else {
		ecs["event"] = map[string]interface{}{"id": data.SessionID, "ingested_by": "spip"}
	}

	if l.ecsChan != nil {
		copied := copyMap(ecs)
		select {
		case l.ecsChan <- copied:
		default:
		}
	}

	return l.writeJSON(ecs)
}

func copyMap(m map[string]interface{}) map[string]interface{} {
	data, err := json.Marshal(m)
	if err != nil {
		return nil
	}
	var out map[string]interface{}
	if json.Unmarshal(data, &out) != nil {
		return nil
	}
	return out
}

// writeJSON writes any value as JSON to the output
func (l *FileLogger) writeJSON(v interface{}) error {
	encoder := json.NewEncoder(l.output)
	if err := encoder.Encode(v); err != nil {
		return fmt.Errorf("failed to encode JSON: %w", err)
	}
	return nil
}

// Debug logs a debug message
func (l *FileLogger) Debug(target, message string) {
	l.Log(LevelDebug, target, message)
}

// Info logs an info message
func (l *FileLogger) Info(target, message string) {
	l.Log(LevelInfo, target, message)
}

// Warn logs a warning message
func (l *FileLogger) Warn(target, message string) {
	l.Log(LevelWarn, target, message)
}

// Error logs an error message
func (l *FileLogger) Error(target, message string) {
	l.Log(LevelError, target, message)
}
