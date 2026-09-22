package config

import (
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
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
	flushIntervalParsed time.Duration
}

type Config struct {
	Name                string `toml:"name"`
	IP                  string `toml:"ip"`
	Port                uint16 `toml:"port"`
	CertPath            string `toml:"cert_path,omitempty"`
	KeyPath             string `toml:"key_path,omitempty"`
	LogFile             string `toml:"log_file,omitempty"`
	ReadTimeoutSeconds  int    `toml:"read_timeout_seconds,omitempty"`
	WriteTimeoutSeconds int    `toml:"write_timeout_seconds,omitempty"`
	RateLimitPerSecond  int    `toml:"rate_limit_per_second,omitempty"`
	RateLimitBurst      int    `toml:"rate_limit_burst,omitempty"`
	CommunityIDSeed     uint16 `toml:"community_id_seed,omitempty"` // optional; 0 = default per Community ID v1 spec
	// CaptureClientHello records the raw TLS ClientHello on each connection
	// as tls.client.hello_hex. Every fingerprint derived from a hello is
	// lossy, so keeping the record is what lets a fingerprint be checked,
	// recomputed or replaced later. Default on; set false to save space.
	CaptureClientHello *bool `toml:"capture_client_hello,omitempty"`
	// IgnoreSources drops connections from these addresses or networks before
	// anything is read, logged or shipped. A honeypot on a rented host is
	// polled by that host's own monitoring, and those scrapes are not attacks:
	// counted, they distort port rankings, scanner counts and fingerprint
	// populations, and they cost storage and bandwidth for records nobody
	// wants. Accepts bare addresses ("192.0.2.10") and CIDR ("192.0.2.0/24"),
	// IPv4 or IPv6.
	IgnoreSources []string   `toml:"ignore_sources,omitempty"`
	Loom          LoomConfig `toml:"loom,omitempty"`

	ignoreNets []netip.Prefix
}

// IgnoredNets returns the parsed ignore list.
func (c *Config) IgnoredNets() []netip.Prefix { return c.ignoreNets }

// ShouldIgnore reports whether traffic from addr must be dropped unrecorded.
func (c *Config) ShouldIgnore(addr netip.Addr) bool {
	if len(c.ignoreNets) == 0 {
		return false
	}
	// A v4-mapped v6 address and its dotted form are the same host, so compare
	// on the unmapped value rather than letting the representation decide.
	addr = addr.Unmap()
	for _, n := range c.ignoreNets {
		if n.Contains(addr) {
			return true
		}
	}
	return false
}

// parseIgnoreSources turns the configured strings into prefixes. A bare
// address becomes a single-host prefix. An unparsable entry is an error rather
// than a silent skip: a typo here means traffic you believe is dropped is
// being recorded.
func parseIgnoreSources(entries []string) ([]netip.Prefix, error) {
	out := make([]netip.Prefix, 0, len(entries))
	for _, raw := range entries {
		e := strings.TrimSpace(raw)
		if e == "" {
			continue
		}
		if strings.Contains(e, "/") {
			p, err := netip.ParsePrefix(e)
			if err != nil {
				return nil, fmt.Errorf("ignore_sources: %q is not a valid network: %w", e, err)
			}
			out = append(out, netip.PrefixFrom(p.Addr().Unmap(), p.Bits()))
			continue
		}
		a, err := netip.ParseAddr(e)
		if err != nil {
			return nil, fmt.Errorf("ignore_sources: %q is not a valid address: %w", e, err)
		}
		a = a.Unmap()
		out = append(out, netip.PrefixFrom(a, a.BitLen()))
	}
	return out, nil
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

	nets, err := parseIgnoreSources(config.IgnoreSources)
	if err != nil {
		return nil, err
	}
	config.ignoreNets = nets

	return &config, nil
}

// ShouldCaptureClientHello defaults to true: a honeypot exists to record what
// arrived, and the hello is the only copy of the cipher order, extension order
// and GREASE placement that every fingerprint discards.
func (c *Config) ShouldCaptureClientHello() bool {
	if c.CaptureClientHello == nil {
		return true
	}
	return *c.CaptureClientHello
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
