// Package controlplane implements tunneld's /api/v1 control-plane API. The
// only endpoint is the unauthenticated POST /api/v1/quick consumed by
// `mcptunnel expose`: it creates an anonymous, ephemeral tenant with one open
// service and returns its agent key.
package controlplane

import (
	"crypto/rand"
	"encoding/json"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/generalpiston/mcptunnels/internal/store"
)

// QuickTTL is how long an anonymous quick-tunnel tenant lives before the
// tunneld janitor deletes it.
const QuickTTL = 24 * time.Hour

// quickRateLimit is the per-remote-IP cap on quick-tunnel creations per hour.
const quickRateLimit = 10

// Server is the control-plane API server.
type Server struct {
	store *store.Store

	quickMu sync.Mutex
	quickIP map[string]*quickWindow // per-remote-IP quick-tunnel rate limit
}

type quickWindow struct {
	windowStart time.Time
	count       int
}

// New builds the control-plane server.
func New(st *store.Store) *Server {
	return &Server{store: st, quickIP: make(map[string]*quickWindow)}
}

// Handler returns the /api/v1 mux (mount it under /api/v1/).
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/v1/quick", s.handleQuick)
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
// random slug (expires after QuickTTL) holding a single open service named
// "mcp", and returns its agent key. The URL is not returned — the control
// plane does not know the public base URL; the CLI builds it from --server.
//
// The abuse guard is deliberately weak: a simple in-memory per-IP rate limit
// (quickRateLimit per hour), which a distributed botnet walks right past.
// Quick tunnels are throwaway; the unguessable URL is the only protection.
func (s *Server) handleQuick(w http.ResponseWriter, r *http.Request) {
	if !s.allowQuick(r.RemoteAddr) {
		writeErr(w, http.StatusTooManyRequests, "quick tunnel rate limit exceeded; try again later")
		return
	}
	expiresAt := time.Now().Add(QuickTTL)
	slug, err := s.createQuickTenant(expiresAt)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "store error")
		return
	}
	agentKey, err := s.store.CreateService(slug, &store.Service{Name: "mcp"})
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "store error")
		return
	}
	slog.Info("controlplane: quick tunnel created", "tenant", slug, "ip", r.RemoteAddr)
	writeJSON(w, http.StatusCreated, map[string]any{
		"tenant":     slug,
		"service":    "mcp",
		"agent_key":  agentKey,
		"expires_at": expiresAt.Unix(),
	})
}

// allowQuick enforces the per-remote-IP quick-tunnel rate limit (fixed
// one-hour windows, in memory — a restart resets it).
func (s *Server) allowQuick(remoteAddr string) bool {
	ip, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		ip = remoteAddr
	}
	s.quickMu.Lock()
	defer s.quickMu.Unlock()
	now := time.Now()
	win, ok := s.quickIP[ip]
	if !ok || now.Sub(win.windowStart) >= time.Hour {
		win = &quickWindow{windowStart: now}
		s.quickIP[ip] = win
	}
	if win.count >= quickRateLimit {
		return false
	}
	win.count++
	return true
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
