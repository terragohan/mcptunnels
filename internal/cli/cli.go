// Package cli holds the plumbing shared by the mcptunnel (user) and
// mcptunnel-admin (operator) binaries: the control-plane HTTP client, the
// on-disk session file, and flag helpers.
package cli

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/generalpiston/openai-tunnel-oauth/internal/config"
)

// Session is the on-disk CLI session (server URL + bearer token).
type Session struct {
	Server string `yaml:"server"`
	Token  string `yaml:"token"`
}

// DefaultSessionPath is the user session; the admin binary uses
// AdminSessionPath so an operator's credential doesn't clobber a user's.
func DefaultSessionPath() (string, error) { return sessionPath("session") }
func AdminSessionPath() (string, error)   { return sessionPath("admin-session") }

func sessionPath(name string) (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".mcptunnel", name), nil
}

// LoadSession reads the session file at path.
func LoadSession(path string) (*Session, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("no session found at %s — log in first", path)
		}
		return nil, err
	}
	var s Session
	if err := yaml.Unmarshal(data, &s); err != nil {
		return nil, fmt.Errorf("parsing %s: %w", path, err)
	}
	if s.Server == "" {
		return nil, fmt.Errorf("session at %s has no server — log in again", path)
	}
	return &s, nil
}

// SaveSession writes the session file at path (mode 0600).
func SaveSession(path string, s *Session) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	data, err := yaml.Marshal(s)
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o600)
}

// Client talks to the control-plane API under /api/v1.
type Client struct {
	Base  string // server URL, no trailing slash
	token string
	hc    *http.Client
}

func NewClient(server, token string) *Client {
	return &Client{
		Base:  strings.TrimRight(server, "/"),
		token: token,
		hc:    &http.Client{Timeout: 30 * time.Second},
	}
}

// Do performs one request. method/path/body as given; out is JSON-decoded if
// non-nil and the response has a body. Non-2xx responses become errors using
// the {"error": "..."} body when present.
func (c *Client) Do(method, path string, query url.Values, body, out any) error {
	u := c.Base + "/api/v1" + path
	if len(query) > 0 {
		u += "?" + query.Encode()
	}
	var rdr io.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			return err
		}
		rdr = bytes.NewReader(data)
	}
	req, err := http.NewRequest(method, u, rdr)
	if err != nil {
		return err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}
	resp, err := c.hc.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		var e struct {
			Error string `json:"error"`
		}
		msg := http.StatusText(resp.StatusCode)
		if json.Unmarshal(data, &e) == nil && e.Error != "" {
			msg = e.Error
		}
		switch resp.StatusCode {
		case http.StatusUnauthorized:
			return fmt.Errorf("unauthorized: %s (check your token; log in again)", msg)
		case http.StatusForbidden:
			if c.token != "" {
				return fmt.Errorf("forbidden: %s (insufficient scope for this token)", msg)
			}
			return fmt.Errorf("forbidden: %s", msg)
		case http.StatusConflict:
			return fmt.Errorf("conflict: %s", msg)
		default:
			return fmt.Errorf("%s: %s", resp.Status, msg)
		}
	}
	if out != nil && len(data) > 0 {
		if err := json.Unmarshal(data, out); err != nil {
			return fmt.Errorf("decoding response: %w", err)
		}
	}
	return nil
}

// ConnFlags holds flags common to all authenticated commands.
type ConnFlags struct {
	Server string
	Token  string
	Config string
}

func (c *ConnFlags) Register(fs *flag.FlagSet) {
	fs.StringVar(&c.Server, "server", "", "server URL (overrides session)")
	fs.StringVar(&c.Token, "token", "", "bearer token (overrides session)")
	fs.StringVar(&c.Config, "config", "", "tunneld.yaml to read the server URL from (same-host use)")
}

// Resolve returns an API client, loading the session at sessionPath for any
// value not given as a flag, then falling back to the public_base_url of
// --config.
func (c *ConnFlags) Resolve(sessionPath string) (*Client, error) {
	server, token := c.Server, c.Token
	if server == "" || token == "" {
		s, err := LoadSession(sessionPath)
		if err == nil {
			if server == "" {
				server = s.Server
			}
			if token == "" {
				token = s.Token
			}
		} else if c.Config == "" {
			return nil, err
		}
	}
	if server == "" && c.Config != "" {
		s, err := ServerFromConfig(c.Config)
		if err != nil {
			return nil, err
		}
		server = s
	}
	if token == "" {
		return nil, fmt.Errorf("no token: pass --token or log in first")
	}
	return NewClient(server, token), nil
}

// ServerFromConfig reads the public_base_url from a tunneld config file.
func ServerFromConfig(path string) (string, error) {
	cfg, err := config.LoadDaemon(path)
	if err != nil {
		return "", err
	}
	return strings.TrimRight(cfg.PublicBaseURL, "/"), nil
}

// SplitRef parses a "<tenant>/<name>" argument.
func SplitRef(arg string) (tenant, name string, err error) {
	parts := strings.SplitN(arg, "/", 2)
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return "", "", fmt.Errorf("expected <tenant>/<name>, got %q", arg)
	}
	return parts[0], parts[1], nil
}

// StringSlice is a repeatable string flag.
type StringSlice []string

func (s *StringSlice) String() string { return strings.Join(*s, ",") }
func (s *StringSlice) Set(v string) error {
	*s = append(*s, v)
	return nil
}

// UsageError makes main exit with code 2 instead of 1.
type UsageError struct{ Err error }

func (UsageError) Error() string { return "usage error" }

func Usagef(format string, args ...any) error {
	return UsageError{Err: fmt.Errorf(format, args...)}
}

// NewFlagSet creates a FlagSet whose parse errors map to exit code 2.
func NewFlagSet(name string) *flag.FlagSet {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	return fs
}

// ParseIntermixed parses flags and positionals in any order (the std flag
// package alone stops at the first positional). It returns the positionals.
func ParseIntermixed(fs *flag.FlagSet, args []string) ([]string, error) {
	var positional []string
	for len(args) > 0 {
		if err := fs.Parse(args); err != nil {
			return nil, err
		}
		args = fs.Args()
		if len(args) == 0 {
			break
		}
		positional = append(positional, args[0])
		args = args[1:]
	}
	return positional, nil
}

func JoinComma(s []string) string { return strings.Join(s, ",") }
