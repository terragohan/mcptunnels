package oauth

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// registerRateLimit is the per-remote-IP cap on DCR registrations per hour.
const registerRateLimit = 20

// registerRate tracks per-IP DCR registration counts in fixed one-hour
// windows. In-memory is fine: a restart just resets the counter.
var registerRate = newIPRate()

// handleRegister implements RFC 7591 Dynamic Client Registration. Public
// clients only (token_endpoint_auth_method: none) — ChatGPT cannot present an
// initial access token, so DCR must be open. Rate-limited per IP.
func (s *Server) handleRegister(w http.ResponseWriter, r *http.Request) {
	if !registerRate.allow(clientIP(r), registerRateLimit) {
		writeErr(w, http.StatusTooManyRequests, "rate_limited", "too many registrations; try again later")
		return
	}

	var req struct {
		RedirectURIs            []string `json:"redirect_uris"`
		TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method"`
		ClientName              string   `json:"client_name"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid_client_metadata", "invalid JSON body")
		return
	}
	if req.TokenEndpointAuthMethod != "" && req.TokenEndpointAuthMethod != "none" {
		writeErr(w, http.StatusBadRequest, "invalid_client_metadata",
			"only public clients (token_endpoint_auth_method=none) are supported")
		return
	}
	if len(req.RedirectURIs) == 0 {
		writeErr(w, http.StatusBadRequest, "invalid_client_metadata", "redirect_uris is required")
		return
	}
	for _, uri := range req.RedirectURIs {
		if !validRedirectURI(uri) {
			writeErr(w, http.StatusBadRequest, "invalid_redirect_uri",
				fmt.Sprintf("redirect_uri %q must be https or a loopback address", uri))
			return
		}
	}

	clientID := "mcp_" + hex.EncodeToString(mustRand(16))
	urisJSON := string(mustJSON(req.RedirectURIs))
	if err := s.store.CreateOAuthClient(s.tenant, clientID, urisJSON); err != nil {
		writeErr(w, http.StatusInternalServerError, "server_error", "failed to store client")
		return
	}

	writeJSON(w, http.StatusCreated, map[string]any{
		"client_id":                  clientID,
		"redirect_uris":              req.RedirectURIs,
		"token_endpoint_auth_method": "none",
		"client_name":                req.ClientName,
	})
}

// validRedirectURI reports whether uri is https or an RFC 8252 loopback
// address (http://127.0.0.1:*, http://[::1]:*, http://localhost:*).
func validRedirectURI(uri string) bool {
	u, err := url.Parse(uri)
	if err != nil {
		return false
	}
	if u.Scheme == "https" {
		return true
	}
	if u.Scheme != "http" {
		return false
	}
	host := u.Hostname()
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// --- per-IP rate limiter ---

type ipRate struct {
	mu    sync.Mutex
	hits  map[string]int
	reset time.Time
}

func newIPRate() *ipRate {
	return &ipRate{hits: make(map[string]int), reset: time.Now().Add(time.Hour)}
}

func (r *ipRate) allow(ip string, limit int) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if time.Now().After(r.reset) {
		r.hits = make(map[string]int)
		r.reset = time.Now().Add(time.Hour)
	}
	r.hits[ip]++
	return r.hits[ip] <= limit
}

func clientIP(r *http.Request) string {
	if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		return host
	}
	if fwd := r.Header.Get("X-Forwarded-For"); fwd != "" {
		if ip, _, _ := strings.Cut(fwd, ","); ip != "" {
			return strings.TrimSpace(ip)
		}
	}
	return r.RemoteAddr
}
