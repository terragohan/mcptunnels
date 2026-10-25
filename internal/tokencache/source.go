package tokencache

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os/exec"
	"strings"
	"sync"
	"time"
)

// skew is the safety margin before expires_at at which a token counts as
// expired; cmdStaleness is how long a token_cmd result is trusted when the
// entry has no expires_at.
const (
	skew         = 30 * time.Second
	cmdStaleness = 5 * time.Minute
)

// Source returns a usable access token for one entry, refreshing when
// needed. A mutex serializes refreshes so concurrent 401s collapse into one.
type Source struct {
	Store *Store
	Entry *Entry

	mu       sync.Mutex
	loadedAt time.Time // when the current access token was obtained
}

// NewSource builds a Source for an entry from the store.
func NewSource(store *Store, e *Entry) *Source {
	return &Source{Store: store, Entry: e, loadedAt: time.Now()}
}

// Token returns a valid access token, refreshing when expired.
func (s *Source) Token(ctx context.Context) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.lockedToken(ctx, false)
}

// Refresh forces a refresh (used after a 401) and returns the new token.
func (s *Source) Refresh(ctx context.Context) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.lockedToken(ctx, true)
}

func (s *Source) lockedToken(ctx context.Context, force bool) (string, error) {
	e := s.Entry
	if !force && e.AccessToken != "" && !expired(e.ExpiresAt) {
		if e.TokenCmd == "" || time.Since(s.loadedAt) < cmdStaleness || e.ExpiresAt != 0 {
			return e.AccessToken, nil
		}
	}
	switch {
	case e.RefreshToken != "" && e.TokenURL != "":
		return s.refreshGrant(ctx)
	case e.TokenCmd != "":
		return s.runCmd(ctx)
	default:
		return "", fmt.Errorf("token for %s is expired and cannot be refreshed; re-run `mcptunnel token add`", e.URL)
	}
}

func expired(expiresAt int64) bool {
	return expiresAt != 0 && expiresAt <= time.Now().Add(skew).Unix()
}

// refreshGrant performs grant_type=refresh_token against the entry's
// token_url and rewrites the entry file with the result.
func (s *Source) refreshGrant(ctx context.Context) (string, error) {
	form := url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {s.Entry.RefreshToken},
	}
	if s.Entry.ClientID != "" {
		form.Set("client_id", s.Entry.ClientID)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.Entry.TokenURL,
		strings.NewReader(form.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	resp, err := (&http.Client{Timeout: 30 * time.Second}).Do(req)
	if err != nil {
		return "", fmt.Errorf("token refresh: %w", err)
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return "", err
	}
	if resp.StatusCode/100 != 2 {
		return "", fmt.Errorf("token refresh: %s: %s", resp.Status, strings.TrimSpace(string(data)))
	}
	var out struct {
		AccessToken  string `json:"access_token"`
		ExpiresIn    int64  `json:"expires_in"`
		RefreshToken string `json:"refresh_token"`
	}
	if err := json.Unmarshal(data, &out); err != nil {
		return "", fmt.Errorf("token refresh: decoding response: %w", err)
	}
	if out.AccessToken == "" {
		return "", fmt.Errorf("token refresh: response has no access_token")
	}
	s.Entry.AccessToken = out.AccessToken
	if out.ExpiresIn > 0 {
		s.Entry.ExpiresAt = time.Now().Unix() + out.ExpiresIn
	}
	if out.RefreshToken != "" {
		s.Entry.RefreshToken = out.RefreshToken
	}
	s.loadedAt = time.Now()
	if s.Store != nil {
		if err := s.Store.Save(s.Entry); err != nil {
			return "", fmt.Errorf("token refresh: saving entry: %w", err)
		}
	}
	return out.AccessToken, nil
}

// runCmd executes the entry's token command; trimmed stdout is the token.
func (s *Source) runCmd(ctx context.Context) (string, error) {
	cmd := exec.CommandContext(ctx, "sh", "-c", s.Entry.TokenCmd)
	out, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("token command %q: %w", s.Entry.TokenCmd, err)
	}
	tok := strings.TrimSpace(string(out))
	if tok == "" {
		return "", fmt.Errorf("token command %q produced no output", s.Entry.TokenCmd)
	}
	s.Entry.AccessToken = tok
	s.loadedAt = time.Now()
	return tok, nil
}
