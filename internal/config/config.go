package config

import (
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/BurntSushi/toml"
)

type LoomConfig struct {
	Enabled            bool   `toml:"enabled"`
	URL                string `toml:"url"`
	SensorID           string `toml:"sensor_id"`
	Token              string `toml:"token"`
	BatchSize          int    `toml:"batch_size"`
	FlushInterval      string `toml:"flush_interval"`
	InsecureSkipVerify bool   `toml:"insecure_skip_verify"`
	// SpoolDir holds the batches waiting for Loom, so an ingest outage is
	// replayed instead of lost. Relative paths resolve against the config
	// file's directory; the default is loom-spool beside config.toml.
	SpoolDir string `toml:"spool_dir,omitempty"`
	// SpoolMaxSizeMB caps the spool (default 512); past it the oldest
	// batches are removed. SpoolMaxAge removes batches older than this
	// (default "7d"; Go durations such as "72h" or a whole number of days
	// followed by "d").
	SpoolMaxSizeMB      int    `toml:"spool_max_size_mb,omitempty"`
	SpoolMaxAge         string `toml:"spool_max_age,omitempty"`
	flushIntervalParsed time.Duration
	spoolMaxAgeParsed   time.Duration
}

// Spool defaults: about 512 MB and a week, sized for a small VPS disk.
const (
	DefaultSpoolDirName = "loom-spool"
	DefaultSpoolMaxMB   = 512
	DefaultSpoolMaxAge  = 7 * 24 * time.Hour
)

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
	IgnoreSources []string `toml:"ignore_sources,omitempty"`
	// UDP capture needs the TPROXY rule from scripts/udp-capture.sh.
	UDPEnabled                  bool       `toml:"udp_enabled,omitempty"`
	UDPPort                     uint16     `toml:"udp_port,omitempty"` // defaults to port
	UDPRateLimitPerSecond       int        `toml:"udp_rate_limit_per_second,omitempty"`
	UDPRateLimitBurst           int        `toml:"udp_rate_limit_burst,omitempty"`
	UDPSourceRateLimitPerSecond int        `toml:"udp_source_rate_limit_per_second,omitempty"`
	UDPSourceRateLimitBurst     int        `toml:"udp_source_rate_limit_burst,omitempty"`
	Loom                        LoomConfig `toml:"loom,omitempty"`

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
	// The spool sits beside config.toml unless told otherwise: on the sensors
	// that is the agent's working directory, which systemd runs it from.
	if config.Loom.SpoolDir == "" {
		config.Loom.SpoolDir = filepath.Join(configDir, DefaultSpoolDirName)
	} else if !filepath.IsAbs(config.Loom.SpoolDir) {
		config.Loom.SpoolDir = filepath.Join(configDir, config.Loom.SpoolDir)
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

// UDPListenPort is the port the UDP listener binds.
func (c *Config) UDPListenPort() uint16 {
	if c.UDPPort != 0 {
		return c.UDPPort
	}
	return c.Port
}

// IsTLSEnabled returns true if both certificate and key paths are configured
func (c *Config) IsTLSEnabled() bool {
	return c.CertPath != "" && c.KeyPath != ""
}

func (l *LoomConfig) FlushIntervalDuration() time.Duration { return l.flushIntervalParsed }

// SpoolMaxAgeDuration is the age past which a spooled batch is removed.
func (l *LoomConfig) SpoolMaxAgeDuration() time.Duration {
	if l.spoolMaxAgeParsed <= 0 {
		return DefaultSpoolMaxAge
	}
	return l.spoolMaxAgeParsed
}

// SpoolMaxBytes is the spool's size cap in bytes.
func (l *LoomConfig) SpoolMaxBytes() int64 {
	if l.SpoolMaxSizeMB <= 0 {
		return DefaultSpoolMaxMB << 20
	}
	return int64(l.SpoolMaxSizeMB) << 20
}

// parseAge reads a Go duration or a whole number of days ("7d").
func parseAge(v string) (time.Duration, error) {
	if days, ok := strings.CutSuffix(v, "d"); ok {
		n, err := strconv.Atoi(days)
		if err != nil || n <= 0 {
			return 0, fmt.Errorf("invalid day count %q", v)
		}
		return time.Duration(n) * 24 * time.Hour, nil
	}
	d, err := time.ParseDuration(v)
	if err != nil || d <= 0 {
		return 0, fmt.Errorf("invalid duration %q", v)
	}
	return d, nil
}

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
	for name, v := range map[string]int{
		"udp_rate_limit_per_second": c.UDPRateLimitPerSecond, "udp_rate_limit_burst": c.UDPRateLimitBurst,
		"udp_source_rate_limit_per_second": c.UDPSourceRateLimitPerSecond, "udp_source_rate_limit_burst": c.UDPSourceRateLimitBurst,
	} {
		if v < 0 {
			return fmt.Errorf("%s must not be negative", name)
		}
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
		if c.Loom.SpoolMaxSizeMB < 0 {
			return fmt.Errorf("loom.spool_max_size_mb must not be negative")
		}
		if c.Loom.SpoolMaxAge != "" {
			age, err := parseAge(c.Loom.SpoolMaxAge)
			if err != nil {
				return fmt.Errorf("loom.spool_max_age must be a positive duration (e.g. 168h or 7d)")
			}
			c.Loom.spoolMaxAgeParsed = age
		}
		if c.Loom.SpoolDir == "" {
			c.Loom.SpoolDir = DefaultSpoolDirName
		}
	}
	return nil
}
