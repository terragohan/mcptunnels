// Package oauth implements tunneld's OAuth 2.1 authorization server:
// discovery metadata, dynamic client registration, the authorize endpoint
// (upstream OIDC brokers or a dev-password login, then a consent screen), the
// token endpoint (authorization_code + PKCE S256, rotating refresh tokens),
// and JWKS.
package oauth

import (
	"crypto/ecdsa"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"

	"github.com/generalpiston/openai-tunnel-oauth/internal/idp"
	"github.com/generalpiston/openai-tunnel-oauth/internal/store"
)

// Config configures the authorization server.
type Config struct {
	// Issuer is the public base URL of this tunneld, e.g.
	// https://tunnel.example.com (no trailing slash).
	Issuer string
	Store  *store.Store

	// TenantSlug scopes all OAuth state (clients, codes, tokens, keys) to one
	// tenant. Empty defaults to store.DefaultTenantSlug.
	TenantSlug string

	// DevUsername / DevPassword are the dev-login credentials, used as the
	// fallback provider when Broker has no providers configured.
	DevUsername string
	DevPassword string

	// Broker holds the upstream OIDC providers (M3). May be nil or empty —
	// then the dev password login is used.
	Broker *idp.Broker

	// AllowedRedirectHosts, when non-empty, restricts DCR and /authorize to
	// redirect_uris whose host is listed (e.g. ["chatgpt.com"]).
	AllowedRedirectHosts []string

	// Rate limits per source IP per minute (defaults: 10 register, 30 token).
	RegisterRatePerMin int
	TokenRatePerMin    int

	AccessTokenTTL  time.Duration // default 15m
	RefreshTokenTTL time.Duration // default 30 days

	// Scopes advertised in metadata (scopes_supported).
	Scopes []string
}

// Server is the OAuth authorization server. Use Handler to mount it and
// ValidateAccessToken to protect proxied routes.
type Server struct {
	issuer          string
	prefix          string // URL path prefix of the issuer ("" or "/t/{tenant}")
	store           *store.Store
	tenantSlug      string
	devUsername     string
	devPassword     string
	broker          *idp.Broker
	accessTokenTTL  time.Duration
	refreshTokenTTL time.Duration
	scopes          []string

	allowedRedirectHosts []string

	kid     string
	privKey *ecdsa.PrivateKey
	privJWK jwk.Key // with kid + alg set
	pubJWK  jwk.Key
	pubSet  jwk.Set

	limiter      *ipLimiter // /register
	tokenLimiter *ipLimiter // /token
}

// NewServer builds the AS, loading (or generating) the ES256 signing key.
func NewServer(cfg Config) (*Server, error) {
	if cfg.Issuer == "" {
		return nil, errors.New("oauth: issuer is required")
	}
	if cfg.Store == nil {
		return nil, errors.New("oauth: store is required")
	}
	if cfg.DevUsername == "" {
		cfg.DevUsername = "dev"
	}
	// An empty dev password disables the dev-password login (used when a
	// tenant has no IdP configured yet).
	if cfg.AccessTokenTTL <= 0 {
		cfg.AccessTokenTTL = 15 * time.Minute
	}
	if cfg.RefreshTokenTTL <= 0 {
		cfg.RefreshTokenTTL = 30 * 24 * time.Hour
	}
	if cfg.RegisterRatePerMin <= 0 {
		cfg.RegisterRatePerMin = 10
	}
	if cfg.TokenRatePerMin <= 0 {
		cfg.TokenRatePerMin = 30
	}

	if cfg.TenantSlug == "" {
		cfg.TenantSlug = store.DefaultTenantSlug
	}

	// The issuer's path component is the URL prefix all HTML form actions and
	// relative redirects must carry (e.g. "/t/acme" for a per-tenant AS).
	prefix := ""
	if u, err := url.Parse(cfg.Issuer); err == nil {
		prefix = strings.TrimRight(u.Path, "/")
	}

	kid, key, err := cfg.Store.SigningKey(cfg.TenantSlug)
	if err != nil {
		return nil, fmt.Errorf("oauth: signing key: %w", err)
	}
	privJWK, err := jwk.FromRaw(key)
	if err != nil {
		return nil, err
	}
	if err := privJWK.Set(jwk.KeyIDKey, kid); err != nil {
		return nil, err
	}
	if err := privJWK.Set(jwk.AlgorithmKey, jwa.ES256); err != nil {
		return nil, err
	}
	pubJWK, err := privJWK.PublicKey()
	if err != nil {
		return nil, err
	}
	if err := pubJWK.Set(jwk.KeyUsageKey, "sig"); err != nil {
		return nil, err
	}
	pubSet := jwk.NewSet()
	pubSet.AddKey(pubJWK)

	return &Server{
		issuer:               cfg.Issuer,
		prefix:               prefix,
		store:                cfg.Store,
		tenantSlug:           cfg.TenantSlug,
		devUsername:          cfg.DevUsername,
		devPassword:          cfg.DevPassword,
		broker:               cfg.Broker,
		accessTokenTTL:       cfg.AccessTokenTTL,
		refreshTokenTTL:      cfg.RefreshTokenTTL,
		scopes:               cfg.Scopes,
		kid:                  kid,
		privKey:              key,
		privJWK:              privJWK,
		pubJWK:               pubJWK,
		pubSet:               pubSet,
		allowedRedirectHosts: cfg.AllowedRedirectHosts,
		limiter:              newIPLimiter(cfg.RegisterRatePerMin, time.Minute),
		tokenLimiter:         newIPLimiter(cfg.TokenRatePerMin, time.Minute),
	}, nil
}

// Handler returns the AS endpoints mux. Mount it at the site root.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /.well-known/oauth-authorization-server", s.handleMetadata)
	mux.HandleFunc("GET /.well-known/oauth-protected-resource", s.handleProtectedResource)
	mux.HandleFunc("GET /.well-known/oauth-protected-resource/", s.handleProtectedResource)
	mux.HandleFunc("POST /register", s.handleRegister)
	mux.HandleFunc("GET /authorize", s.handleAuthorizeGet)
	mux.HandleFunc("POST /authorize", s.handleAuthorizePost)
	mux.HandleFunc("POST /authorize/consent", s.handleConsentPost)
	mux.HandleFunc("GET /idp/{name}/login", s.handleIdpLogin)
	mux.HandleFunc("GET /idp/{name}/callback", s.handleIdpCallback)
	mux.HandleFunc("POST /token", s.handleToken)
	mux.HandleFunc("GET /jwks.json", s.handleJWKS)
	return securityHeaders(mux)
}

// securityHeaders sets minimal hardening headers on all AS responses.
func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "no-referrer")
		// The authorize/consent pages must never be framed (clickjacking).
		h.Set("Content-Security-Policy", "frame-ancestors 'none'")
		next.ServeHTTP(w, r)
	})
}

// audit appends an audit entry; failures are logged at debug level and never
// break the request path.
func (s *Server) audit(event, subject, clientID, service, ip string, detail map[string]string) {
	d := "{}"
	if len(detail) > 0 {
		if b, err := json.Marshal(detail); err == nil {
			d = string(b)
		}
	}
	if err := s.store.LogAudit(s.tenantSlug, store.AuditEntry{
		Event:    event,
		Subject:  subject,
		ClientID: clientID,
		Service:  service,
		IP:       ip,
		Detail:   d,
	}); err != nil {
		slog.Debug("oauth: audit write failed", "event", event, "err", err)
	}
}

// redirectHostAllowed enforces the optional redirect-host allowlist. With no
// allowlist configured every (https) host is accepted.
func (s *Server) redirectHostAllowed(uri string) bool {
	if len(s.allowedRedirectHosts) == 0 {
		return true
	}
	u, err := url.Parse(uri)
	if err != nil {
		return false
	}
	return slices.Contains(s.allowedRedirectHosts, u.Hostname())
}

// randomString returns n cryptographically random bytes, base64url-encoded.
func randomString(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err) // crypto/rand failure is unrecoverable
	}
	return base64.RawURLEncoding.EncodeToString(b)
}
