package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadConfig(t *testing.T) {
	// Create a temporary directory for test files
	tmpDir, err := os.MkdirTemp("", "spip-test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	// Test cases
	tests := []struct {
		name         string
		content      string
		wantErr      bool
		validateIP   string
		validatePort uint16
		validateUDP  bool
	}{
		{
			name: "valid config",
			content: `
				name = "test-agent"
				ip = "127.0.0.1"
				port = 12345
				cert_path = "cert.pem"
				key_path = "key.pem"
			`,
			wantErr:      false,
			validateIP:   "127.0.0.1",
			validatePort: 12345,
		},
		{
			name: "minimal config",
			content: `
				name = "test-agent"
				ip = "0.0.0.0"
				port = 8080
			`,
			wantErr:      false,
			validateIP:   "0.0.0.0",
			validatePort: 8080,
		},
		{
			name: "udp enabled",
			content: `
				name = "test-agent"
				ip = "0.0.0.0"
				port = 8080
				udp_enabled = true
			`,
			wantErr:      false,
			validateIP:   "0.0.0.0",
			validatePort: 8080,
			validateUDP:  true,
		},
		{
			name: "invalid TOML",
			content: `
				ip = "127.0.0.1"
				port = "not a number"
			`,
			wantErr: true,
		},
		{
			name: "loom enabled valid",
			content: `
name = "test-agent"
ip = "127.0.0.1"
port = 8080
[loom]
enabled = true
url = "https://loom.local/ingest"
sensor_id = "sensor-1"
token = "secret"
flush_interval = "5s"
			`,
			wantErr:      false,
			validateIP:   "127.0.0.1",
			validatePort: 8080,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create test config file
			configPath := filepath.Join(tmpDir, "config.toml")
			if err := os.WriteFile(configPath, []byte(tt.content), 0644); err != nil {
				t.Fatalf("Failed to write config file: %v", err)
			}

			// Load and test config
			cfg, err := LoadConfig(configPath)
			if (err != nil) != tt.wantErr {
				t.Errorf("LoadConfig() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !tt.wantErr {
				if cfg.IP != tt.validateIP {
					t.Errorf("LoadConfig() IP = %v, want %v", cfg.IP, tt.validateIP)
				}
				if cfg.Port != tt.validatePort {
					t.Errorf("LoadConfig() Port = %v, want %v", cfg.Port, tt.validatePort)
				}
				if cfg.UDPEnabled != tt.validateUDP {
					t.Errorf("LoadConfig() UDPEnabled = %v, want %v", cfg.UDPEnabled, tt.validateUDP)
				}
			}
		})
	}
}

func TestConfigValidation(t *testing.T) {
	tests := []struct {
		name    string
		config  Config
		wantErr bool
	}{
		{
			name: "valid config",
			config: Config{
				Name: "test-agent",
				IP:   "127.0.0.1",
				Port: 12345,
			},
			wantErr: false,
		},
		{
			name: "missing IP",
			config: Config{
				Port: 12345,
			},
			wantErr: true,
		},
		{
			name: "missing port",
			config: Config{
				IP: "127.0.0.1",
			},
			wantErr: true,
		},
		{
			name: "incomplete TLS config",
			config: Config{
				IP:       "127.0.0.1",
				Port:     12345,
				CertPath: "cert.pem",
			},
			wantErr: true,
		},
		{
			name: "loom enabled missing url",
			config: Config{
				Name: "x", IP: "127.0.0.1", Port: 8080,
				Loom: LoomConfig{Enabled: true, SensorID: "s", Token: "t"},
			},
			wantErr: true,
		},
		{
			name: "loom enabled missing token",
			config: Config{
				Name: "x", IP: "127.0.0.1", Port: 8080,
				Loom: LoomConfig{Enabled: true, URL: "https://x", SensorID: "s"},
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("Config.Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestIsTLSEnabled(t *testing.T) {
	tests := []struct {
		name     string
		config   Config
		expected bool
	}{
		{
			name: "TLS enabled",
			config: Config{
				CertPath: "cert.pem",
				KeyPath:  "key.pem",
			},
			expected: true,
		},
		{
			name:     "TLS disabled",
			config:   Config{},
			expected: false,
		},
		{
			name: "TLS partially configured",
			config: Config{
				CertPath: "cert.pem",
			},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.config.IsTLSEnabled(); got != tt.expected {
				t.Errorf("Config.IsTLSEnabled() = %v, want %v", got, tt.expected)
			}
		})
	}
}
