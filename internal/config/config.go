// Package config loads and validates the YAML configuration for tunneld.
package config

import (
	"fmt"
	"os"
	"time"

	"gopkg.in/yaml.v3"
)

// TLSMode selects how tunneld terminates TLS.
type TLSMode string

const (
	// TLSModeACME obtains certificates automatically via Let's Encrypt.
	TLSModeACME TLSMode = "acme"
	// TLSModeManual uses explicit cert/key files.
	TLSModeManual TLSMode = "manual"
	// TLSModeDisabled serves plain HTTP (development only).
	TLSModeDisabled TLSMode = "disabled"
)

// DaemonConfig is the configuration for tunneld.
type DaemonConfig struct {
	// Listen is the address the public listener binds to.
	Listen string `yaml:"listen"`
	// PublicBaseURL is the externally visible base URL, e.g.
	// https://tunnel.example.com. Its host is used for the ACME allowlist,
	// and `mcptunnel expose --config` reads it to find the server.
	PublicBaseURL string `yaml:"public_base_url"`
	TLS           struct {
		Mode TLSMode `yaml:"mode"`
		ACME struct {
			CacheDir string `yaml:"cache_dir"`
			Email    string `yaml:"email"`
		} `yaml:"acme"`
		Manual struct {
			CertFile string `yaml:"cert_file"`
			KeyFile  string `yaml:"key_file"`
		} `yaml:"manual"`
	} `yaml:"tls"`

	// DatabasePath is the SQLite database file. Defaults to
	// ./data/tunneld.db; may also be supplied via the DATABASE_PATH
	// environment variable.
	DatabasePath string `yaml:"database_path"`
}

// Duration is a time.Duration that unmarshals from YAML strings like "5s".
type Duration time.Duration

// UnmarshalYAML implements yaml.Unmarshaler.
func (d *Duration) UnmarshalYAML(value *yaml.Node) error {
	var s string
	if err := value.Decode(&s); err != nil {
		return err
	}
	v, err := time.ParseDuration(s)
	if err != nil {
		return fmt.Errorf("invalid duration %q: %w", s, err)
	}
	*d = Duration(v)
	return nil
}

// D returns the value as a time.Duration.
func (d Duration) D() time.Duration { return time.Duration(d) }

// AgentConfig carries the agent connection parameters. `mcptunnel expose`
// builds one in memory from the quick-tunnel response; it is not read from a
// file anymore.
type AgentConfig struct {
	// Server is the base WebSocket URL of tunneld, e.g.
	// wss://tunnel.example.com (the connect path is appended automatically).
	Server   string `yaml:"server"`
	Tenant   string `yaml:"tenant"`
	AgentKey string `yaml:"agent_key"`
	Service  string `yaml:"service"`
	// Upstream is the local HTTP base URL requests are forwarded to, e.g.
	// http://localhost:3000.
	Upstream  string `yaml:"upstream"`
	Reconnect struct {
		InitialBackoff Duration `yaml:"initial_backoff"`
		MaxBackoff     Duration `yaml:"max_backoff"`
	} `yaml:"reconnect"`
}

// LoadDaemon reads and validates a tunneld config file.
func LoadDaemon(path string) (*DaemonConfig, error) {
	cfg := &DaemonConfig{
		Listen: ":443",
	}
	cfg.TLS.Mode = TLSModeACME
	if err := load(path, cfg); err != nil {
		return nil, err
	}
	if cfg.DatabasePath == "" {
		cfg.DatabasePath = os.Getenv("DATABASE_PATH")
	}
	if cfg.DatabasePath == "" {
		cfg.DatabasePath = "./data/tunneld.db"
	}
	if cfg.PublicBaseURL == "" {
		return nil, fmt.Errorf("public_base_url is required")
	}
	switch cfg.TLS.Mode {
	case TLSModeACME:
		if cfg.TLS.ACME.CacheDir == "" {
			cfg.TLS.ACME.CacheDir = "./acme-cache"
		}
	case TLSModeManual:
		if cfg.TLS.Manual.CertFile == "" || cfg.TLS.Manual.KeyFile == "" {
			return nil, fmt.Errorf("tls.manual.cert_file and key_file are required for tls mode %q", cfg.TLS.Mode)
		}
	case TLSModeDisabled:
		// plain HTTP, nothing extra needed
	default:
		return nil, fmt.Errorf("unknown tls mode %q (want acme, manual or disabled)", cfg.TLS.Mode)
	}
	return cfg, nil
}

func load(path string, out any) error {
	f, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("open config %s: %w", path, err)
	}
	defer f.Close()
	dec := yaml.NewDecoder(f)
	dec.KnownFields(true)
	if err := dec.Decode(out); err != nil {
		return fmt.Errorf("parse config %s: %w", path, err)
	}
	return nil
}
