// Package tokencache is a per-user registry of bearer tokens keyed by
// upstream URL, with automatic refresh. Both `mcptunnel expose --url` and
// `mcptunnel run --url` look entries up here instead of requiring a static
// secret in a flag or env var. Entries live under
// $(os.UserConfigDir())/mcptunnels/tokens/, one 0600 JSON file per upstream
// named by the SHA-256 of the normalized URL.
package tokencache

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
)

// Entry is one stored token record for an upstream URL.
type Entry struct {
	URL          string `json:"url"`
	AccessToken  string `json:"access_token,omitempty"`
	ExpiresAt    int64  `json:"expires_at,omitempty"` // unix seconds; zero = never expires
	RefreshToken string `json:"refresh_token,omitempty"`
	TokenURL     string `json:"token_url,omitempty"`
	ClientID     string `json:"client_id,omitempty"`
	TokenCmd     string `json:"token_cmd,omitempty"`
}

// SourceType describes how an entry produces a token, for display.
func (e *Entry) SourceType() string {
	switch {
	case e.TokenCmd != "":
		return "command"
	case e.RefreshToken != "":
		return "refreshable"
	default:
		return "static"
	}
}

// NormalizeURL canonicalizes an upstream URL for keying: lowercase scheme
// and host, default ports dropped, no trailing slash.
func NormalizeURL(raw string) (string, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return "", fmt.Errorf("invalid URL %q", raw)
	}
	u.Scheme = strings.ToLower(u.Scheme)
	u.Host = strings.ToLower(u.Host)
	if (u.Scheme == "http" && strings.HasSuffix(u.Host, ":80")) ||
		(u.Scheme == "https" && strings.HasSuffix(u.Host, ":443")) {
		u.Host = u.Host[:strings.LastIndex(u.Host, ":")]
	}
	u.Path = strings.TrimRight(u.Path, "/")
	u.RawQuery = ""
	u.Fragment = ""
	return u.String(), nil
}

func key(raw string) (string, error) {
	n, err := NormalizeURL(raw)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256([]byte(n))
	return hex.EncodeToString(sum[:]) + ".json", nil
}

// Store reads and writes entry files under Dir.
type Store struct {
	Dir string // empty → $(os.UserConfigDir())/mcptunnels/tokens
}

// DefaultStore returns a Store at the per-user config location.
func DefaultStore() *Store { return &Store{} }

func (s *Store) dir() (string, error) {
	if s.Dir != "" {
		return s.Dir, nil
	}
	base, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(base, "mcptunnels", "tokens"), nil
}

func (s *Store) path(rawURL string) (string, error) {
	k, err := key(rawURL)
	if err != nil {
		return "", err
	}
	d, err := s.dir()
	if err != nil {
		return "", err
	}
	return filepath.Join(d, k), nil
}

// Save writes the entry atomically (temp file + rename), 0600.
func (s *Store) Save(e *Entry) error {
	p, err := s.path(e.URL)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(p), 0700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(e, "", "  ")
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(p), ".tmp-*.json")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if err := tmp.Chmod(0600); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), p)
}

// Lookup returns the entry for rawURL, or nil when absent.
func (s *Store) Lookup(rawURL string) (*Entry, error) {
	p, err := s.path(rawURL)
	if err != nil {
		return nil, err
	}
	data, err := os.ReadFile(p)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var e Entry
	if err := json.Unmarshal(data, &e); err != nil {
		return nil, fmt.Errorf("reading token entry %s: %w", p, err)
	}
	return &e, nil
}

// Remove deletes the entry for rawURL; absent is not an error.
func (s *Store) Remove(rawURL string) error {
	p, err := s.path(rawURL)
	if err != nil {
		return err
	}
	if err := os.Remove(p); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

// List returns all stored entries (unreadable files are skipped).
func (s *Store) List() ([]*Entry, error) {
	d, err := s.dir()
	if err != nil {
		return nil, err
	}
	fis, err := os.ReadDir(d)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var out []*Entry
	for _, fi := range fis {
		if !strings.HasSuffix(fi.Name(), ".json") {
			continue
		}
		data, err := os.ReadFile(filepath.Join(d, fi.Name()))
		if err != nil {
			continue
		}
		var e Entry
		if json.Unmarshal(data, &e) == nil {
			out = append(out, &e)
		}
	}
	return out, nil
}

// Transport injects Authorization: Bearer <token> from Source into every
// request. On a 401 it force-refreshes once and retries the request.
type Transport struct {
	Source *Source
	Base   http.RoundTripper // nil → http.DefaultTransport
}

func (t *Transport) RoundTrip(req *http.Request) (*http.Response, error) {
	base := t.Base
	if base == nil {
		base = http.DefaultTransport
	}
	tok, err := t.Source.Token(req.Context())
	if err != nil {
		return nil, err
	}
	setAuth(req, tok)
	resp, err := base.RoundTrip(req)
	if err != nil || resp.StatusCode != http.StatusUnauthorized {
		return resp, err
	}
	// One forced refresh + retry. The retry needs a re-readable body; MCP
	// requests are small and already buffered by the caller's http.Client
	// via GetBody, so refuse when it isn't replayable.
	resp.Body.Close()
	if req.Body != nil && req.GetBody == nil {
		return nil, fmt.Errorf("upstream returned 401 and the request body is not replayable")
	}
	tok, err = t.Source.Refresh(req.Context())
	if err != nil {
		return nil, err
	}
	retry := req.Clone(req.Context())
	if req.GetBody != nil {
		retry.Body, err = req.GetBody()
		if err != nil {
			return nil, err
		}
	}
	setAuth(retry, tok)
	return base.RoundTrip(retry)
}

func setAuth(req *http.Request, token string) {
	if req.Header == nil {
		req.Header = http.Header{}
	}
	req.Header.Set("Authorization", "Bearer "+token)
}
