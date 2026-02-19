package config

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/BurntSushi/toml"
)

type LoomConfig struct {
	Enabled             bool   `toml:"enabled"`
	URL                 string `toml:"url"`
	SensorID            string `toml:"sensor_id"`
	Token               string `toml:"token"`
	BatchSize           int    `toml:"batch_size"`
	FlushInterval       string `toml:"flush_interval"`
	InsecureSkipVerify  bool   `toml:"insecure_skip_verify"`
	flushIntervalParsed  time.Duration
}

type Config struct {
	Name               string `toml:"name"`
	IP                 string `toml:"ip"`
	Port               uint16 `toml:"port"`
	CertPath           string `toml:"cert_path,omitempty"`
	KeyPath            string `toml:"key_path,omitempty"`
	LogFile            string `toml:"log_file,omitempty"`
	ReadTimeoutSeconds int    `toml:"read_timeout_seconds,omitempty"`
	WriteTimeoutSeconds int   `toml:"write_timeout_seconds,omitempty"`
	RateLimitPerSecond int    `toml:"rate_limit_per_second,omitempty"`
	RateLimitBurst     int    `toml:"rate_limit_burst,omitempty"`
	CommunityIDSeed    uint16 `toml:"community_id_seed,omitempty"` // optional; 0 = default per Community ID v1 spec
	Loom               LoomConfig `toml:"loom,omitempty"`
}

func LoadConfig(path string) (*Config, error) {
	content, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	var config Config
	if err := toml.Unmarshal(content, &config); err != nil {
		return nil, fmt.Errorf("failed to parse config file: %w", err)
	}

	// Resolve relative cert/key paths relative to the config file's directory
	configDir := filepath.Dir(path)
	if config.CertPath != "" && !filepath.IsAbs(config.CertPath) {
		config.CertPath = filepath.Join(configDir, config.CertPath)
	}
	if config.KeyPath != "" && !filepath.IsAbs(config.KeyPath) {
		config.KeyPath = filepath.Join(configDir, config.KeyPath)
	}

	return &config, nil
}

// IsTLSEnabled returns true if both certificate and key paths are configured
func (c *Config) IsTLSEnabled() bool {
	return c.CertPath != "" && c.KeyPath != ""
}

func (l *LoomConfig) FlushIntervalDuration() time.Duration { return l.flushIntervalParsed }

func (c *Config) Validate() error {
	if c.Name == "" {
		return fmt.Errorf("name is required in configuration")
	}
	if c.IP == "" {
		return fmt.Errorf("IP address is required")
	}
	if c.Port == 0 {
		return fmt.Errorf("port is required")
	}
	if (c.CertPath != "" && c.KeyPath == "") || (c.CertPath == "" && c.KeyPath != "") {
		return fmt.Errorf("both cert_path and key_path must be provided for TLS")
	}
	if c.Loom.Enabled {
		if c.Loom.URL == "" {
			return fmt.Errorf("loom.url is required when loom.enabled is true")
		}
		if c.Loom.SensorID == "" {
			return fmt.Errorf("loom.sensor_id is required when loom.enabled is true")
		}
		if c.Loom.Token == "" {
			return fmt.Errorf("loom.token is required when loom.enabled is true")
		}
		if c.Loom.BatchSize <= 0 {
			c.Loom.BatchSize = 50
		}
		d := c.Loom.FlushInterval
		if d == "" {
			d = "10s"
		}
		parsed, err := time.ParseDuration(d)
		if err != nil || parsed <= 0 {
			return fmt.Errorf("loom.flush_interval must be a positive duration (e.g. 10s)")
		}
		c.Loom.flushIntervalParsed = parsed
	}
	return nil
}
