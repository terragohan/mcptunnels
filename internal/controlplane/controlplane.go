// Package controlplane implements the /api/v1 control-plane API consumed by
// the mcptunnel CLI. All endpoints (except bootstrap) require
// "Authorization: Bearer <token>" resolving to an operator token (global) or a
// tenant admin token (scoped to its tenant).
package controlplane

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/generalpiston/openai-tunnel-oauth/internal/store"
)

// Invalidator drops cached per-tenant authorization-server state (signing
// keys, IdP configs). *oauth.Resolver implements it.
type Invalidator interface {
	Invalidate(tenant string)
}

// Server is the control-plane API server.
type Server struct {
	store *store.Store
	inv   Invalidator // may be nil (tests)

	// OnBootstrap, when set, is called after a successful bootstrap. tunneld
	// uses it to delete the on-disk setup-token file.
	OnBootstrap func()
}

// New builds the control-plane server. Bootstrap is accepted only while no
// operator tokens exist and requires a one-time setup token from the store
// (tunneld creates and prints one on first run). inv, when given, is
// invalidated on idp set/delete, keys rotate and tenant delete/disable.
func New(st *store.Store, inv Invalidator) *Server {
	return &Server{store: st, inv: inv}
}

// invalidate drops the tenant's cached AS state, if an Invalidator is wired.
func (s *Server) invalidate(tenant string) {
	if s.inv != nil {
		s.inv.Invalidate(tenant)
	}
}

// principal is the authenticated caller.
type principal struct {
	tenantSlug string // "" for operators
	isOperator bool
}

type ctxKey struct{}

func principalOf(r *http.Request) *principal {
	p, _ := r.Context().Value(ctxKey{}).(*principal)
	return p
}

// Handler returns the /api/v1 mux (mount it under /api/v1/).
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/v1/bootstrap", s.handleBootstrap)
	mux.HandleFunc("POST /api/v1/signup", s.handleSignup)

	// Authenticated routes.
	authed := func(pattern string, h http.HandlerFunc) {
		mux.Handle(pattern, s.requireAuth(h))
	}
	authed("POST /api/v1/invites", s.requireOperator(s.handleCreateInvite))
	authed("GET /api/v1/tenants", s.requireOperator(s.handleListTenants))
	authed("DELETE /api/v1/tenants/{slug}", s.requireOperator(s.handleDeleteTenant))
	authed("POST /api/v1/tenants/{slug}/disable", s.requireOperator(s.handleDisableTenant))
	authed("POST /api/v1/tenants/{slug}/enable", s.requireOperator(s.handleEnableTenant))
	authed("POST /api/v1/tenants/{slug}/token/rotate", s.handleRotateToken)
	authed("POST /api/v1/tenants/{slug}/password", s.handleResetPassword)
	authed("POST /api/v1/tenants/{slug}/services", s.handleCreateService)
	authed("GET /api/v1/tenants/{slug}/services", s.handleListServices)
	authed("DELETE /api/v1/tenants/{slug}/services/{name}", s.handleDeleteService)
	authed("POST /api/v1/tenants/{slug}/services/{name}/agent-key", s.handleIssueAgentKey)
	authed("PUT /api/v1/tenants/{slug}/idp", s.handleSetIDP)
	authed("GET /api/v1/tenants/{slug}/idp", s.handleListIDP)
	authed("DELETE /api/v1/tenants/{slug}/idp", s.handleDeleteIDP)
	authed("GET /api/v1/tenants/{slug}/audit", s.handleAudit)
	authed("POST /api/v1/tenants/{slug}/keys/rotate", s.handleRotateKeys)
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

func (s *Server) requireAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		token, ok := strings.CutPrefix(auth, "Bearer ")
		if !ok || token == "" {
			w.Header().Set("WWW-Authenticate", "Bearer")
			writeErr(w, http.StatusUnauthorized, "missing bearer token")
			return
		}
		slug, isOp, err := s.store.ValidateToken(token)
		if err != nil {
			writeErr(w, http.StatusUnauthorized, "invalid token")
			return
		}
		next(w, r.WithContext(context.WithValue(r.Context(), ctxKey{}, &principal{tenantSlug: slug, isOperator: isOp})))
	}
}

func (s *Server) requireOperator(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !principalOf(r).isOperator {
			writeErr(w, http.StatusForbidden, "operator token required")
			return
		}
		next(w, r)
	}
}

// requireTenantAccess allows operators everywhere and tenant admins only on
// their own tenant ({slug} path value).
func (s *Server) requireTenantAccess(w http.ResponseWriter, r *http.Request) (string, bool) {
	p := principalOf(r)
	slug := r.PathValue("slug")
	if !p.isOperator && p.tenantSlug != slug {
		writeErr(w, http.StatusForbidden, "token is scoped to a different tenant")
		return "", false
	}
	return slug, true
}

func validSlug(slug string) bool {
	if slug == "" || len(slug) > 64 {
		return false
	}
	for _, c := range slug {
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
			return false
		}
	}
	return true
}

func (s *Server) audit(tenantSlug, event, subject, service, ip string) {
	if err := s.store.LogAudit(tenantSlug, store.AuditEntry{
		Event:   event,
		Subject: subject,
		Service: service,
		IP:      ip,
	}); err != nil {
		slog.Debug("controlplane: audit write failed", "event", event, "err", err)
	}
}

// --- bootstrap ---

func (s *Server) handleBootstrap(w http.ResponseWriter, r *http.Request) {
	var body struct {
		SetupToken string `json:"setup_token"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	ok, err := s.store.ConsumeSetupToken(body.SetupToken)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "store error")
		return
	}
	if !ok {
		writeErr(w, http.StatusForbidden, "invalid setup token")
		return
	}
	has, err := s.store.HasOperatorTokens()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "store error")
		return
	}
	if has {
		writeErr(w, http.StatusConflict, "bootstrap already completed")
		return
	}
	token, err := s.store.CreateOperatorToken()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "store error")
		return
	}
	slog.Info("controlplane: bootstrap completed, operator token issued")
	if s.OnBootstrap != nil {
		s.OnBootstrap()
	}
	writeJSON(w, http.StatusCreated, map[string]string{"token": token})
}

// --- signup (invite-gated self-service) ---

// handleSignup is the public, invite-gated tenant self-registration: one
// invite code creates one tenant and returns its tenant admin token. The
// invite is the abuse gate, so no separate rate limiter lives here.
func (s *Server) handleSignup(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Slug        string `json:"slug"`
		DisplayName string `json:"display_name"`
		Invite      string `json:"invite"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	if !validSlug(body.Slug) {
		writeErr(w, http.StatusBadRequest, "slug must be 1-64 chars of [a-z0-9-]")
		return
	}
	// Check availability before consuming the invite so a slug conflict
	// doesn't burn the caller's code.
	if _, err := s.store.GetTenant(body.Slug); err == nil {
		writeErr(w, http.StatusConflict, "tenant already exists")
		return
	} else if !errors.Is(err, store.ErrNotFound) {
		writeErr(w, http.StatusInternalServerError, "store error")
		return
	}
	ok, err := s.store.ConsumeInvite(body.Invite)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "store error")
		return
	}
	if !ok {
		writeErr(w, http.StatusForbidden, "invalid invite code")
		return
	}
	if err := s.store.CreateTenant(body.Slug, body.DisplayName); err != nil {
		if errors.Is(err, store.ErrExists) {
			writeErr(w, http.StatusConflict, "tenant already exists")
			return
		}
		writeErr(w, http.StatusInternalServerError, "store error")
		return
	}
	token, err := s.store.CreateTenantToken(body.Slug)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "store error")
		return
	}
	password := store.NewLoginPassword()
	if err := s.store.SetTenantLoginPassword(body.Slug, password); err != nil {
		writeErr(w, http.StatusInternalServerError, "store error")
		return
	}
	s.audit(body.Slug, "tenant.signup", "", "", r.RemoteAddr)
	writeJSON(w, http.StatusCreated, map[string]string{
		"slug":     body.Slug,
		"token":    token,
		"password": password,
	})
}

// handleCreateInvite mints a one-time signup invite code (operator only).
func (s *Server) handleCreateInvite(w http.ResponseWriter, r *http.Request) {
	code, err := s.store.CreateInvite()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "store error")
		return
	}
	slog.Info("controlplane: invite created", "ip", r.RemoteAddr)
	writeJSON(w, http.StatusCreated, map[string]string{"invite": code})
}

// --- tenants ---

func (s *Server) handleListTenants(w http.ResponseWriter, r *http.Request) {
	tenants, err := s.store.ListTenants()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "store error")
		return
	}
	type tenantJSON struct {
		Slug        string `json:"slug"`
		DisplayName string `json:"display_name"`
		CreatedAt   int64  `json:"created_at"`
		DisabledAt  *int64 `json:"disabled_at,omitempty"`
	}
	out := []tenantJSON{}
	for _, t := range tenants {
		j := tenantJSON{Slug: t.Slug, DisplayName: t.DisplayName, CreatedAt: t.CreatedAt.Unix()}
		if t.DisabledAt != nil {
			v := t.DisabledAt.Unix()
			j.DisabledAt = &v
		}
		out = append(out, j)
	}
	writeJSON(w, http.StatusOK, map[string]any{"tenants": out})
}

func (s *Server) handleDeleteTenant(w http.ResponseWriter, r *http.Request) {
	slug := r.PathValue("slug")
	ok, err := s.store.DeleteTenant(slug)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "store error")
		return
	}
	if !ok {
		writeErr(w, http.StatusNotFound, "tenant not found")
		return
	}
	// No audit row: the tenant (and its audit log) is gone.
	s.invalidate(slug)
	w.WriteHeader(http.StatusNoContent)
}

// handleDisableTenant marks the tenant disabled: its public endpoints
// (/t/{slug}/...) start returning 404 once the cached AS is invalidated.
func (s *Server) handleDisableTenant(w http.ResponseWriter, r *http.Request) {
	s.setTenantDisabled(w, r, true)
}

func (s *Server) handleEnableTenant(w http.ResponseWriter, r *http.Request) {
	s.setTenantDisabled(w, r, false)
}

func (s *Server) setTenantDisabled(w http.ResponseWriter, r *http.Request, disabled bool) {
	slug := r.PathValue("slug")
	var err error
	if disabled {
		err = s.store.DisableTenant(slug)
	} else {
		err = s.store.EnableTenant(slug)
	}
	if errors.Is(err, store.ErrNotFound) {
		writeErr(w, http.StatusNotFound, "tenant not found")
		return
	}
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "store error")
		return
	}
	event := "tenant.enabled"
	if disabled {
		event = "tenant.disabled"
	}
	s.audit(slug, event, "", "", r.RemoteAddr)
	s.invalidate(slug)
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleRotateToken(w http.ResponseWriter, r *http.Request) {
	slug, ok := s.requireTenantAccess(w, r)
	if !ok {
		return
	}
	token, err := s.store.RotateTenantToken(slug)
	if errors.Is(err, store.ErrNotFound) {
		writeErr(w, http.StatusNotFound, "tenant not found")
		return
	}
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "store error")
		return
	}
	s.audit(slug, "token.rotated", "", "", r.RemoteAddr)
	writeJSON(w, http.StatusOK, map[string]string{"token": token})
}

// handleResetPassword issues a new OAuth dev-login password for the tenant,
// replacing the old one.
func (s *Server) handleResetPassword(w http.ResponseWriter, r *http.Request) {
	slug, ok := s.requireTenantAccess(w, r)
	if !ok {
		return
	}
	password := store.NewLoginPassword()
	if err := s.store.SetTenantLoginPassword(slug, password); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeErr(w, http.StatusNotFound, "tenant not found")
			return
		}
		writeErr(w, http.StatusInternalServerError, "store error")
		return
	}
	s.audit(slug, "password.reset", "", "", r.RemoteAddr)
	writeJSON(w, http.StatusOK, map[string]string{"password": password})
}

// --- services ---

type serviceJSON struct {
	Name           string `json:"name"`
	AuthMode       string `json:"auth_mode"`
	IdentitySecret string `json:"identity_secret,omitempty"`
	CreatedAt      int64  `json:"created_at"`
}

func (s *Server) handleCreateService(w http.ResponseWriter, r *http.Request) {
	slug, ok := s.requireTenantAccess(w, r)
	if !ok {
		return
	}
	var body struct {
		Name           string `json:"name"`
		AuthMode       string `json:"auth_mode"`
		IdentitySecret string `json:"identity_secret"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	if !validSlug(body.Name) {
		writeErr(w, http.StatusBadRequest, "service name must be 1-64 chars of [a-z0-9-]")
		return
	}
	switch body.AuthMode {
	case "", "strict":
		body.AuthMode = "strict"
	case "discovery_open":
	default:
		writeErr(w, http.StatusBadRequest, "auth_mode must be strict or discovery_open")
		return
	}
	agentKey, err := s.store.CreateService(slug, &store.Service{
		Name:           body.Name,
		IdentitySecret: body.IdentitySecret,
		AuthMode:       body.AuthMode,
	})
	if err != nil {
		switch {
		case errors.Is(err, store.ErrNotFound):
			writeErr(w, http.StatusNotFound, "tenant not found")
		case errors.Is(err, store.ErrExists):
			writeErr(w, http.StatusConflict, "service already exists")
		default:
			writeErr(w, http.StatusInternalServerError, "store error")
		}
		return
	}
	s.audit(slug, "service.created", "", body.Name, r.RemoteAddr)
	writeJSON(w, http.StatusCreated, map[string]any{
		"service":   serviceJSON{Name: body.Name, AuthMode: body.AuthMode, CreatedAt: time.Now().Unix()},
		"agent_key": agentKey,
	})
}

func (s *Server) handleListServices(w http.ResponseWriter, r *http.Request) {
	slug, ok := s.requireTenantAccess(w, r)
	if !ok {
		return
	}
	svcs, err := s.store.ListServices(slug)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "store error")
		return
	}
	out := []serviceJSON{}
	for _, svc := range svcs {
		out = append(out, serviceJSON{
			Name:      svc.Name,
			AuthMode:  svc.AuthMode,
			CreatedAt: svc.CreatedAt.Unix(),
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{"services": out})
}

func (s *Server) handleDeleteService(w http.ResponseWriter, r *http.Request) {
	slug, ok := s.requireTenantAccess(w, r)
	if !ok {
		return
	}
	name := r.PathValue("name")
	okDel, err := s.store.DeleteService(slug, name)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "store error")
		return
	}
	if !okDel {
		writeErr(w, http.StatusNotFound, "service not found")
		return
	}
	s.audit(slug, "service.deleted", "", name, r.RemoteAddr)
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleIssueAgentKey(w http.ResponseWriter, r *http.Request) {
	slug, ok := s.requireTenantAccess(w, r)
	if !ok {
		return
	}
	name := r.PathValue("name")
	agentKey, err := s.store.RotateAgentKey(slug, name)
	if errors.Is(err, store.ErrNotFound) {
		writeErr(w, http.StatusNotFound, "service not found")
		return
	}
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "store error")
		return
	}
	s.audit(slug, "agent_key.issued", "", name, r.RemoteAddr)
	writeJSON(w, http.StatusOK, map[string]string{"agent_key": agentKey})
}

// --- IdP configs ---

func (s *Server) handleSetIDP(w http.ResponseWriter, r *http.Request) {
	slug, ok := s.requireTenantAccess(w, r)
	if !ok {
		return
	}
	var body struct {
		Name           string   `json:"name"`
		ClientID       string   `json:"client_id"`
		ClientSecret   string   `json:"client_secret"`
		Issuer         string   `json:"issuer"`
		AllowedEmails  []string `json:"allowed_emails"`
		AllowedDomains []string `json:"allowed_domains"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	if !validSlug(body.Name) || body.ClientID == "" || body.ClientSecret == "" || body.Issuer == "" {
		writeErr(w, http.StatusBadRequest, "name, client_id, client_secret and issuer are required")
		return
	}
	cfg := &store.IDPConfig{
		Name:           body.Name,
		ClientID:       body.ClientID,
		ClientSecret:   body.ClientSecret,
		Issuer:         body.Issuer,
		AllowedEmails:  body.AllowedEmails,
		AllowedDomains: body.AllowedDomains,
	}
	if err := s.store.SetIDP(slug, cfg); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeErr(w, http.StatusNotFound, "tenant not found")
			return
		}
		writeErr(w, http.StatusInternalServerError, "store error")
		return
	}
	s.invalidate(slug)
	s.audit(slug, "idp.configured", body.Name, "", r.RemoteAddr)
	writeJSON(w, http.StatusOK, map[string]string{"name": body.Name})
}

type idpJSON struct {
	Name           string   `json:"name"`
	ClientID       string   `json:"client_id"`
	Issuer         string   `json:"issuer"`
	AllowedEmails  []string `json:"allowed_emails"`
	AllowedDomains []string `json:"allowed_domains"`
}

func (s *Server) handleListIDP(w http.ResponseWriter, r *http.Request) {
	slug, ok := s.requireTenantAccess(w, r)
	if !ok {
		return
	}
	cfgs, err := s.store.ListIDP(slug)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "store error")
		return
	}
	out := []idpJSON{}
	for _, c := range cfgs {
		// client_secret is never returned.
		out = append(out, idpJSON{
			Name:           c.Name,
			ClientID:       c.ClientID,
			Issuer:         c.Issuer,
			AllowedEmails:  c.AllowedEmails,
			AllowedDomains: c.AllowedDomains,
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{"idps": out})
}

func (s *Server) handleDeleteIDP(w http.ResponseWriter, r *http.Request) {
	slug, ok := s.requireTenantAccess(w, r)
	if !ok {
		return
	}
	name := r.URL.Query().Get("name")
	if name == "" {
		writeErr(w, http.StatusBadRequest, "name query parameter is required")
		return
	}
	okDel, err := s.store.DeleteIDP(slug, name)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "store error")
		return
	}
	if !okDel {
		writeErr(w, http.StatusNotFound, "idp config not found")
		return
	}
	s.invalidate(slug)
	s.audit(slug, "idp.deleted", name, "", r.RemoteAddr)
	w.WriteHeader(http.StatusNoContent)
}

// --- audit ---

func (s *Server) handleAudit(w http.ResponseWriter, r *http.Request) {
	slug, ok := s.requireTenantAccess(w, r)
	if !ok {
		return
	}
	n := 50
	if v := r.URL.Query().Get("n"); v != "" {
		if parsed, err := strconv.Atoi(v); err == nil && parsed > 0 {
			n = parsed
		}
	}
	entries, err := s.store.ListAudit(slug, n)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "store error")
		return
	}
	type entryJSON struct {
		TS       int64  `json:"ts"`
		Event    string `json:"event"`
		Subject  string `json:"subject"`
		ClientID string `json:"client_id"`
		Service  string `json:"service"`
		IP       string `json:"ip"`
		Detail   string `json:"detail"`
	}
	out := []entryJSON{}
	for _, e := range entries {
		out = append(out, entryJSON{
			TS: e.TS.Unix(), Event: e.Event, Subject: e.Subject,
			ClientID: e.ClientID, Service: e.Service, IP: e.IP, Detail: e.Detail,
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{"entries": out})
}

// --- signing keys ---

func (s *Server) handleRotateKeys(w http.ResponseWriter, r *http.Request) {
	slug, ok := s.requireTenantAccess(w, r)
	if !ok {
		return
	}
	kid, _, err := s.store.RotateSigningKey(slug)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "store error")
		return
	}
	s.invalidate(slug)
	s.audit(slug, "keys.rotated", kid, "", r.RemoteAddr)
	writeJSON(w, http.StatusOK, map[string]string{
		"kid":  kid,
		"note": "active immediately; outstanding access tokens are invalidated",
	})
}
