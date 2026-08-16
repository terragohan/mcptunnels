// Package config loads and validates the YAML configuration for tunneld and
// tunnel-agent.
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

// Auth modes for a service.
const (
	// AuthModeStrict requires a valid access token for every request.
	AuthModeStrict = "strict"
	// AuthModeDiscoveryOpen lets unauthenticated MCP initialize/ping/
	// tools/list requests (and the SSE GET) through; everything else needs a
	// token. Works around ChatGPT's scanner connecting without OAuth.
	AuthModeDiscoveryOpen = "discovery_open"
)

// IdPProvider is an upstream OIDC identity provider tunneld brokers to.
type IdPProvider struct {
	Name         string `yaml:"name"` // e.g. "google"; used in /idp/{name}/... paths
	ClientID     string `yaml:"client_id"`
	ClientSecret string `yaml:"client_secret"`
	Issuer       string `yaml:"issuer"` // OIDC discovery base, e.g. https://accounts.google.com
	// AllowedEmails / AllowedDomains restrict who may log in. Empty = anyone
	// the provider authenticates.
	AllowedEmails  []string `yaml:"allowed_emails"`
	AllowedDomains []string `yaml:"allowed_domains"`
}

// DaemonConfig is the configuration for tunneld.
type DaemonConfig struct {
	// Listen is the address the public listener binds to.
	Listen string `yaml:"listen"`
	// PublicBaseURL is the externally visible base URL, e.g.
	// https://tunnel.example.com. Its host is used for the ACME allowlist.
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

	// DevAuth is the M2 dev-login: a single static user, marked
	// not-for-production. Real IdP brokering lands in M3.
	DevAuth struct {
		Username string `yaml:"username"`
		Password string `yaml:"password"`
	} `yaml:"dev_auth"`

	// Tokens controls OAuth token lifetimes.
	Tokens struct {
		AccessTTL  Duration `yaml:"access_ttl"`  // default 15m
		RefreshTTL Duration `yaml:"refresh_ttl"` // default 720h (30 days)
	} `yaml:"tokens"`

	// Scopes are the supported scopes advertised in the AS metadata.
	Scopes []string `yaml:"scopes"`

	// IdP lists upstream OIDC providers for real user identity. Deprecated in
	// v2: per-tenant IdPs are managed via `mcptunnel idp set` and stored in
	// the database; this field is only kept so old configs still parse. When a
	// tenant has no IdP configured, the dev_auth password login is used.
	IdP []IdPProvider `yaml:"idp"`

	// OAuth holds AS hardening options.
	OAuth struct {
		// AllowedRedirectHosts, when set, restricts DCR and /authorize to
		// redirect_uris on these hosts (e.g. ["chatgpt.com"]).
		AllowedRedirectHosts []string `yaml:"allowed_redirect_hosts"`
	} `yaml:"oauth"`
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

// AgentConfig is the configuration for tunnel-agent.
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
	cfg.DevAuth.Username = "dev"
	cfg.Tokens.AccessTTL = Duration(15 * time.Minute)
	cfg.Tokens.RefreshTTL = Duration(30 * 24 * time.Hour)
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
		return nil, fmt.Errorf("public_base_url is required (it is the OAuth issuer)")
	}
	if cfg.Tokens.AccessTTL <= 0 {
		return nil, fmt.Errorf("tokens.access_ttl must be positive")
	}
	if cfg.Tokens.RefreshTTL <= 0 {
		return nil, fmt.Errorf("tokens.refresh_ttl must be positive")
	}
	for i, p := range cfg.IdP {
		if p.Name == "" || p.ClientID == "" || p.ClientSecret == "" || p.Issuer == "" {
			return nil, fmt.Errorf("idp[%d]: name, client_id, client_secret and issuer are required", i)
		}
		for _, c := range p.Name {
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
				return nil, fmt.Errorf("idp[%d]: name %q must be lowercase alphanumeric plus '-'", i, p.Name)
			}
		}
	}
	// M1: the public OAuth surface is disabled, so dev_auth is optional.
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

// LoadAgent reads and validates a tunnel-agent config file.
func LoadAgent(path string) (*AgentConfig, error) {
	cfg := &AgentConfig{}
	cfg.Reconnect.InitialBackoff = Duration(time.Second)
	cfg.Reconnect.MaxBackoff = Duration(30 * time.Second)
	if err := load(path, cfg); err != nil {
		return nil, err
	}
	if cfg.Server == "" {
		return nil, fmt.Errorf("server is required")
	}
	if cfg.Tenant == "" {
		return nil, fmt.Errorf("tenant is required")
	}
	if cfg.AgentKey == "" {
		return nil, fmt.Errorf("agent_key is required")
	}
	if cfg.Service == "" {
		return nil, fmt.Errorf("service is required")
	}
	if cfg.Upstream == "" {
		return nil, fmt.Errorf("upstream is required")
	}
	if cfg.Reconnect.InitialBackoff <= 0 {
		cfg.Reconnect.InitialBackoff = Duration(time.Second)
	}
	if cfg.Reconnect.MaxBackoff <= 0 {
		cfg.Reconnect.MaxBackoff = Duration(30 * time.Second)
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
