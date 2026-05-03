//go:build e2e
// +build e2e

package e2e

import (
	"encoding/json"
	"fmt"
	"time"
)

// LogEntry represents the JSON log format output by the SPIP agent
type LogEntry struct {
	Timestamp       int64  `json:"timestamp"`
	Level           string `json:"level,omitempty"`
	Message         string `json:"message,omitempty"`
	Target          string `json:"target,omitempty"`
	RecordType      string `json:"record_type,omitempty"`
	Payload         string `json:"payload,omitempty"`
	PayloadHex      string `json:"payload_hex,omitempty"`
	SourceIP        string `json:"source_ip,omitempty"`
	SourcePort      int    `json:"source_port,omitempty"`
	DestinationIP   string `json:"destination_ip,omitempty"`
	DestinationPort int    `json:"destination_port,omitempty"`
	SessionID       string `json:"session_id,omitempty"`
	IsTLS           bool   `json:"is_tls,omitempty"`
	TLSVersion      string `json:"tls_version,omitempty"`
	TLSCipherSuite  string `json:"tls_cipher_suite,omitempty"`
	// Fingerprinting (ECS)
	CommunityID           string   `json:"community_id,omitempty"`
	TLSServerName         string   `json:"tls_server_name,omitempty"`
	TLSSupportedProtocols []string `json:"tls_supported_protocols,omitempty"`
	TLSJA4                string   `json:"tls_ja4,omitempty"`
	HTTPJA4H              string   `json:"http_ja4h,omitempty"`
	SSHHassh              string   `json:"ssh_hassh,omitempty"`
}

// ValidateLogEntry validates a single log entry against expected values
func ValidateLogEntry(entry *LogEntry, expectedPayload string, expectedIsTLS bool) error {
	if entry == nil {
		return fmt.Errorf("log entry is nil")
	}

	// Basic validation
	if entry.Timestamp == 0 {
		return fmt.Errorf("timestamp is missing")
	}

	if entry.SessionID == "" {
		return fmt.Errorf("session_id is missing")
	}

	// Validate payload if provided
	if expectedPayload != "" && entry.Payload != expectedPayload {
		return fmt.Errorf("payload mismatch: got %q, want %q", entry.Payload, expectedPayload)
	}

	// Validate TLS flag
	if entry.IsTLS != expectedIsTLS {
		return fmt.Errorf("TLS flag mismatch: got %v, want %v", entry.IsTLS, expectedIsTLS)
	}

	// Validate IP addresses and ports
	if entry.SourceIP == "" || entry.DestinationIP == "" {
		return fmt.Errorf("source or destination IP is missing")
	}

	if entry.SourcePort == 0 || entry.DestinationPort == 0 {
		return fmt.Errorf("source or destination port is missing")
	}

	return nil
}

// ParseLogLine parses a JSON log line into a LogEntry struct
func ParseLogLine(line string) (*LogEntry, error) {
	// Parse into a generic map and extract known fields (supports ECS-shaped output)
	var m map[string]interface{}
	if err := json.Unmarshal([]byte(line), &m); err != nil {
		return nil, err
	}

	entry := &LogEntry{}

	// @timestamp (RFC3339) -> Unix
	if tsRaw, ok := m["@timestamp"]; ok {
		if tsStr, ok := tsRaw.(string); ok && tsStr != "" {
			if t, err := time.Parse(time.RFC3339Nano, tsStr); err == nil {
				entry.Timestamp = t.Unix()
			} else if t, err := time.Parse(time.RFC3339, tsStr); err == nil {
				entry.Timestamp = t.Unix()
			}
		}
	} else if tsRaw, ok := m["timestamp"]; ok {
		// fallback to numeric timestamp
		switch v := tsRaw.(type) {
		case float64:
			entry.Timestamp = int64(v)
		case int64:
			entry.Timestamp = v
		}
	}

	// event.id -> session id
	if ev, ok := m["event"].(map[string]interface{}); ok {
		if id, ok := ev["id"].(string); ok {
			entry.SessionID = id
		}
	}

	// payload fields - prefer `event.summary` (non-HTTP payloads), then http.request.body, then legacy keys
	// 1) event.summary (non-HTTP payloads)
	if ev, ok := m["event"].(map[string]interface{}); ok {
		if summary, ok := ev["summary"].(string); ok {
			entry.Payload = summary
		}
	}

	// 2) http.request.body.content (HTTP payloads) - only used if event.summary wasn't present
	if entry.Payload == "" {
		if httpObj, ok := m["http"].(map[string]interface{}); ok {
			if req, ok := httpObj["request"].(map[string]interface{}); ok {
				if bodyObj, ok := req["body"].(map[string]interface{}); ok {
					if content, ok := bodyObj["content"].(string); ok {
						entry.Payload = content
					}
				}
			}
		}
	}

	// 3) legacy top-level payload
	if entry.Payload == "" {
		if p, ok := m["payload"].(string); ok {
			entry.Payload = p
		}
	}

	// payload hex - prefer event.original_payload_hex, then fallback
	if ev, ok := m["event"].(map[string]interface{}); ok {
		if oph, ok := ev["original_payload_hex"].(string); ok {
			entry.PayloadHex = oph
		}
	}
	if entry.PayloadHex == "" {
		if ph, ok := m["payload_hex"].(string); ok {
			entry.PayloadHex = ph
		}
	}

	// source and destination
	if src, ok := m["source"].(map[string]interface{}); ok {
		if sip, ok := src["ip"].(string); ok {
			entry.SourceIP = sip
		}
		if sport, ok := src["port"]; ok {
			switch v := sport.(type) {
			case float64:
				entry.SourcePort = int(v)
			case int:
				entry.SourcePort = v
			}
		}
	}
	if dst, ok := m["destination"].(map[string]interface{}); ok {
		if dip, ok := dst["ip"].(string); ok {
			entry.DestinationIP = dip
		}
		if dport, ok := dst["port"]; ok {
			switch v := dport.(type) {
			case float64:
				entry.DestinationPort = int(v)
			case int:
				entry.DestinationPort = v
			}
		}
	}

	// network.protocol -> IsTLS, network.community_id
	if netObj, ok := m["network"].(map[string]interface{}); ok {
		if proto, ok := netObj["protocol"].(string); ok {
			if proto == "tls" || proto == "https" {
				entry.IsTLS = true
			}
		}
		if cid, ok := netObj["community_id"].(string); ok {
			entry.CommunityID = cid
		}
	}

	// tls.client.server_name, tls.client.supported_protocols, tls.client.hash.ja4
	if tlsObj, ok := m["tls"].(map[string]interface{}); ok {
		if client, ok := tlsObj["client"].(map[string]interface{}); ok {
			if sn, ok := client["server_name"].(string); ok {
				entry.TLSServerName = sn
			}
			if ja4, ok := client["hash"].(map[string]interface{}); ok {
				if s, ok := ja4["ja4"].(string); ok {
					entry.TLSJA4 = s
				}
			}
			if protos, ok := client["supported_protocols"].([]interface{}); ok {
				for _, p := range protos {
					if s, ok := p.(string); ok {
						entry.TLSSupportedProtocols = append(entry.TLSSupportedProtocols, s)
					}
				}
			}
		}
	}

	// http.request.hash.ja4h
	if httpObj, ok := m["http"].(map[string]interface{}); ok {
		if req, ok := httpObj["request"].(map[string]interface{}); ok {
			if hash, ok := req["hash"].(map[string]interface{}); ok {
				if ja4h, ok := hash["ja4h"].(string); ok {
					entry.HTTPJA4H = ja4h
				}
			}
		}
	}

	// ssh.client.hash.hassh
	if sshObj, ok := m["ssh"].(map[string]interface{}); ok {
		if client, ok := sshObj["client"].(map[string]interface{}); ok {
			if hash, ok := client["hash"].(map[string]interface{}); ok {
				if hassh, ok := hash["hassh"].(string); ok {
					entry.SSHHassh = hassh
				}
			}
		}
	}

	return entry, nil
}
