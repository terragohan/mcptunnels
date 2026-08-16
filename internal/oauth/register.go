package oauth

import (
	"encoding/json"
	"net"
	"net/http"
	"net/url"
	"slices"
	"time"

	"github.com/generalpiston/openai-tunnel-oauth/internal/store"
)

// registerRequest is the RFC 7591 client-metadata subset we accept.
type registerRequest struct {
	RedirectURIs            []string `json:"redirect_uris"`
	ClientName              string   `json:"client_name"`
	GrantTypes              []string `json:"grant_types"`
	TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method"`
	Scope                   string   `json:"scope"`
}

// registerResponse is the RFC 7591 client-information response.
type registerResponse struct {
	ClientID                string   `json:"client_id"`
	ClientIDIssuedAt        int64    `json:"client_id_issued_at"`
	ClientSecretExpiresAt   int64    `json:"client_secret_expires_at"`
	RedirectURIs            []string `json:"redirect_uris"`
	ClientName              string   `json:"client_name"`
	GrantTypes              []string `json:"grant_types"`
	TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method"`
}

// handleRegister implements open Dynamic Client Registration (RFC 7591).
// Open by necessity — ChatGPT cannot present an initial access token — so it
// is rate-limited per source IP.
func (s *Server) handleRegister(w http.ResponseWriter, r *http.Request) {
	if !s.limiter.allow(clientIP(r)) {
		writeJSONError(w, http.StatusTooManyRequests, "too_many_requests", "registration rate limit exceeded")
		return
	}

	var req registerRequest
	if err := decodeJSON(r, &req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid_client_metadata", "malformed JSON body")
		return
	}
	if len(req.RedirectURIs) == 0 {
		writeJSONError(w, http.StatusBadRequest, "invalid_redirect_uri", "redirect_uris must be non-empty")
		return
	}
	for _, u := range req.RedirectURIs {
		parsed, err := url.Parse(u)
		if err != nil || parsed.Host == "" ||
			(parsed.Scheme != "https" && !isLoopbackRedirect(parsed)) {
			writeJSONError(w, http.StatusBadRequest, "invalid_redirect_uri", "redirect_uris must be absolute https:// URLs (http allowed for loopback only, RFC 8252)")
			return
		}
		if !s.redirectHostAllowed(u) {
			writeJSONError(w, http.StatusBadRequest, "invalid_redirect_uri", "redirect_uri host is not allowed on this server")
			return
		}
	}
	grantTypes := req.GrantTypes
	if len(grantTypes) == 0 {
		grantTypes = []string{"authorization_code"}
	}
	for _, g := range grantTypes {
		if g != "authorization_code" && g != "refresh_token" {
			writeJSONError(w, http.StatusBadRequest, "invalid_client_metadata", "unsupported grant_type "+g)
			return
		}
	}

	client := &store.Client{
		ClientID:     randomString(16),
		ClientName:   req.ClientName,
		RedirectURIs: req.RedirectURIs,
		GrantTypes:   grantTypes,
		CreatedAt:    time.Now(),
	}
	if err := s.store.InsertClient(s.tenantSlug, client); err != nil {
		writeJSONError(w, http.StatusInternalServerError, "server_error", "could not store client")
		return
	}
	s.audit("client_registered", "", client.ClientID, "", clientIP(r), map[string]string{
		"client_name": client.ClientName,
	})

	writeJSON(w, http.StatusCreated, registerResponse{
		ClientID:                client.ClientID,
		ClientIDIssuedAt:        client.CreatedAt.Unix(),
		ClientSecretExpiresAt:   0, // public client: no secret
		RedirectURIs:            client.RedirectURIs,
		ClientName:              client.ClientName,
		GrantTypes:              client.GrantTypes,
		TokenEndpointAuthMethod: "none",
	})
}

func clientIP(r *http.Request) string {
	if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		return host
	}
	return r.RemoteAddr
}

func decodeJSON(r *http.Request, v any) error {
	return json.NewDecoder(r.Body).Decode(v)
}

// isLoopbackRedirect reports whether u is an http URL on a loopback address
// (127.0.0.0/8, ::1 or localhost), which RFC 8252 §7.3 permits for native
// apps — e.g. CLI MCP clients like Codex.
func isLoopbackRedirect(u *url.URL) bool {
	if u.Scheme != "http" {
		return false
	}
	h := u.Hostname()
	if h == "localhost" {
		return true
	}
	ip := net.ParseIP(h)
	return ip != nil && ip.IsLoopback()
}

// redirectURIRegistered reports whether uri exactly matches one of the
// client's registered redirect URIs.
func redirectURIRegistered(c *store.Client, uri string) bool {
	return slices.Contains(c.RedirectURIs, uri)
}
