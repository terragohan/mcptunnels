// Package controlplane implements tunneld's /api/v1 control-plane API. The
// only endpoint is the unauthenticated POST /api/v1/quick consumed by
// `mcptunnel expose`: it creates an anonymous, ephemeral tenant with one
// service (OAuth-gated by default) and returns its agent key.
package controlplane

import (
	"crypto/rand"
	"encoding/json"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/terragohan/mcptunnels/internal/oauth"
	"github.com/terragohan/mcptunnels/internal/store"
)

// QuickTTL is how long an anonymous quick-tunnel tenant lives before the
// tunneld janitor deletes it.
const QuickTTL = 24 * time.Hour

// quickRateLimit is the per-remote-IP cap on quick-tunnel creations per hour.
const quickRateLimit = 10

// maxLiveTunnels caps the number of non-expired tenants; POST /api/v1/quick
// refuses new tunnels with 503 once the cap is reached.
const maxLiveTunnels = 500

// Server is the control-plane API server.
type Server struct {
	store *store.Store
}

// New builds the control-plane server.
func New(st *store.Store) *Server {
	return &Server{store: st}
}

// Handler returns the /api/v1 mux (mount it under /api/v1/).
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/v1/quick", s.handleQuick)
	mux.HandleFunc("DELETE /api/v1/quick/{tenant}", s.handleDelete)
	return mux
}

// --- helpers ---

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

// --- quick tunnels (anonymous, ephemeral) ---

// handleQuick creates an anonymous quick tunnel: an ephemeral tenant with a
// random slug (expires after QuickTTL) holding a single service named "mcp",
// and returns its agent key. The URL is not returned — the control plane does
// not know the public base URL; the CLI builds it from --server.
//
// The request body may be empty or {"auth": true|false}. Default is true:
// the service is OAuth-gated and an ES256 signing key is generated for the
// tenant. With auth=false the service is created with auth_mode "open".
//
// The abuse guard is deliberately weak: a simple per-IP rate limit
// (quickRateLimit per hour, persisted in the store so a restart does not
// reset it), which a distributed botnet walks right past.
// Quick tunnels are throwaway; the unguessable URL is the only protection.
func (s *Server) handleQuick(w http.ResponseWriter, r *http.Request) {
	if !s.allowQuick(r.RemoteAddr) {
		writeErr(w, http.StatusTooManyRequests, "quick tunnel rate limit exceeded; try again later")
		return
	}
	live, err := s.store.CountLiveTenants(time.Now())
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "store error")
		return
	}
	if live >= maxLiveTunnels {
		writeErr(w, http.StatusServiceUnavailable, "service at capacity, try again later")
		return
	}

	// Parse optional auth + password. Absent body or absent key defaults to
	// auth=true. Password is required when auth is true; it gates the OAuth
	// authorize endpoint.
	auth := true
	var password string
	if r.ContentLength > 0 {
		var req struct {
			Auth     *bool  `json:"auth"`
			Password string `json:"password"`
		}
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&req); err != nil {
			writeErr(w, http.StatusBadRequest, "invalid JSON body")
			return
		}
		if req.Auth != nil {
			auth = *req.Auth
		}
		password = req.Password
	}
	if auth && password == "" {
		writeErr(w, http.StatusBadRequest, "password is required when auth is enabled")
		return
	}

	expiresAt := time.Now().Add(QuickTTL)
	slug, err := s.createQuickTenant(expiresAt)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "store error")
		return
	}

	authMode := "oauth"
	if !auth {
		authMode = "open"
	}
	svc := &store.Service{Name: "mcp", AuthMode: authMode}
	if auth && password != "" {
		hash, err := store.HashSecret(password)
		if err != nil {
			writeErr(w, http.StatusInternalServerError, "hash error")
			return
		}
		svc.PasswordHash = hash
	}
	agentKey, err := s.store.CreateService(slug, svc)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "store error")
		return
	}

	// Generate the tenant's OAuth signing key when auth is enabled.
	if auth {
		pemStr, err := oauth.GenerateKey()
		if err != nil {
			writeErr(w, http.StatusInternalServerError, "key generation failed")
			return
		}
		if err := s.store.CreateSigningKey(slug, pemStr); err != nil {
			writeErr(w, http.StatusInternalServerError, "store error")
			return
		}
	}

	slog.Info("controlplane: quick tunnel created", "tenant", slug, "auth", auth, "ip", r.RemoteAddr)
	writeJSON(w, http.StatusCreated, map[string]any{
		"tenant":     slug,
		"service":    "mcp",
		"agent_key":  agentKey,
		"expires_at": expiresAt.Unix(),
	})
}

// handleDelete destroys a quick tunnel: the tenant and everything under it
// (service, signing key, OAuth clients, auth codes) are deleted via cascade.
// Authenticated with the agent key — the same credential the agent uses to
// connect. Called by `mcptunnel expose` on graceful shutdown.
func (s *Server) handleDelete(w http.ResponseWriter, r *http.Request) {
	tenant := r.PathValue("tenant")
	service := r.Header.Get("X-Service-Name")
	key := strings.TrimSpace(strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "))
	if service == "" || key == "" {
		writeErr(w, http.StatusUnauthorized, "X-Service-Name and Authorization: Bearer <agent_key> are required")
		return
	}
	if _, err := s.store.ValidateAgentKey(tenant, service, key); err != nil {
		writeErr(w, http.StatusUnauthorized, "invalid agent key")
		return
	}
	ok, err := s.store.DeleteTenant(tenant)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "store error")
		return
	}
	if !ok {
		writeErr(w, http.StatusNotFound, "tenant not found")
		return
	}
	slog.Info("controlplane: quick tunnel deleted", "tenant", tenant, "ip", r.RemoteAddr)
	w.WriteHeader(http.StatusNoContent)
}

// allowQuick enforces the per-remote-IP quick-tunnel rate limit (fixed
// one-hour windows, persisted in the store so a restart does not reset it).
// A store error fails open: a broken counter should not take down signups.
func (s *Server) allowQuick(remoteAddr string) bool {
	ip, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		ip = remoteAddr
	}
	count, err := s.store.QuickRateHit(ip, time.Now())
	if err != nil {
		slog.Warn("controlplane: quick rate-limit check failed, allowing", "err", err)
		return true
	}
	return count <= quickRateLimit
}

// quickSlugAlphabet is [a-z0-9] for random quick-tunnel slugs.
const quickSlugAlphabet = "abcdefghijklmnopqrstuvwxyz0123456789"

// createQuickTenant inserts an ephemeral tenant with a random "q-xxxxxxxxxx"
// slug, retrying on the (astronomically unlikely) collision.
func (s *Server) createQuickTenant(expiresAt time.Time) (string, error) {
	for range 10 {
		var b [10]byte
		if _, err := rand.Read(b[:]); err != nil {
			return "", err
		}
		var sb strings.Builder
		sb.WriteString("q-")
		for _, c := range b {
			sb.WriteByte(quickSlugAlphabet[int(c)%len(quickSlugAlphabet)])
		}
		slug := sb.String()
		err := s.store.CreateTenantExpiry(slug, "quick tunnel", &expiresAt)
		if errors.Is(err, store.ErrExists) {
			continue
		}
		if err != nil {
			return "", err
		}
		return slug, nil
	}
	return "", store.ErrExists
}
