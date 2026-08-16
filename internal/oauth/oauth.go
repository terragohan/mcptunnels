package oauth

import (
	"crypto/ecdsa"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/terragohan/mcptunnels/internal/store"
)

// Server is a per-tenant OAuth 2.1 authorization server. It serves the
// authorize, token, register, jwks, and metadata endpoints under the tenant's
// issuer path.
type Server struct {
	issuer     string // e.g. "https://host/t/q-abc123"
	baseURL    string // e.g. "https://host"
	tenant     string
	store      *store.Store
	signingKey *ecdsa.PrivateKey
	expiresAt  time.Time // tenant expiry — access tokens live this long
}

// NewServer builds an AS for one tenant. The signing key is loaded from (or
// generated into) the store.
func NewServer(st *store.Store, baseURL, tenant string, expiresAt time.Time) (*Server, error) {
	pemStr, err := st.GetSigningKey(tenant)
	if err != nil {
		// Generate and store a new key.
		pemStr, err = GenerateKey()
		if err != nil {
			return nil, err
		}
		if err := st.CreateSigningKey(tenant, pemStr); err != nil {
			return nil, err
		}
	}
	key, err := parseKey(pemStr)
	if err != nil {
		return nil, err
	}
	return &Server{
		issuer:     strings.TrimRight(baseURL, "/") + "/t/" + tenant,
		baseURL:    strings.TrimRight(baseURL, "/"),
		tenant:     tenant,
		store:      st,
		signingKey: key,
		expiresAt:  expiresAt,
	}, nil
}

// tenantExpiresAt returns when access tokens for this tenant should expire.
func (s *Server) tenantExpiresAt() time.Time {
	return s.expiresAt
}

// Handler returns the endpoint mux for this tenant. The caller is expected to
// strip the "/t/{tenant}" prefix before dispatching.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /authorize", s.handleAuthorize)
	mux.HandleFunc("POST /authorize", s.handleAuthorize)
	mux.HandleFunc("POST /token", s.handleToken)
	mux.HandleFunc("POST /register", s.handleRegister)
	mux.HandleFunc("GET /jwks.json", jwksHandler(&s.signingKey.PublicKey))
	mux.HandleFunc("GET /.well-known/oauth-authorization-server", s.asMetadata)
	return s.withSecurityHeaders(mux)
}

// ValidateAccessToken verifies a bearer token against this tenant's signing
// key. It is the entry point used by the public proxy.
func (s *Server) ValidateAccessToken(tokenString string) (*AccessClaims, error) {
	return validateAccessToken(&s.signingKey.PublicKey, s.issuer, tokenString)
}

// withSecurityHeaders wraps h with OWASP-recommended response headers for an
// OAuth AS.
func (s *Server) withSecurityHeaders(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Content-Security-Policy", "frame-ancestors 'none'")
		h.ServeHTTP(w, r)
	})
}

// --- Resolver ---

// Resolver maps tenant slugs to their OAuth Server instances, caching them.
// It also routes the well-known metadata endpoints that live outside the
// /t/{tenant} prefix.
type Resolver struct {
	store   *store.Store
	baseURL string

	mu      sync.Mutex
	servers map[string]*Server
}

// BaseURL returns the public base URL the resolver was constructed with.
func (r *Resolver) BaseURL() string { return r.baseURL }

// NewResolver returns a Resolver that builds per-tenant AS instances backed by
// st, with issuer URLs derived from baseURL.
func NewResolver(st *store.Store, baseURL string) *Resolver {
	return &Resolver{
		store:   st,
		baseURL: strings.TrimRight(baseURL, "/"),
		servers: make(map[string]*Server),
	}
}

// server returns the (cached) OAuth Server for tenant, creating it on first
// access. Returns nil when the tenant does not exist.
func (r *Resolver) server(tenant string) *Server {
	r.mu.Lock()
	defer r.mu.Unlock()
	if srv, ok := r.servers[tenant]; ok {
		return srv
	}
	tn, err := r.store.GetTenant(tenant)
	if err != nil {
		return nil
	}
	expiresAt := time.Now().Add(24 * time.Hour) // fallback
	if tn.ExpiresAt != nil {
		expiresAt = *tn.ExpiresAt
	}
	srv, err := NewServer(r.store, r.baseURL, tenant, expiresAt)
	if err != nil {
		return nil
	}
	r.servers[tenant] = srv
	return srv
}

// Validator returns the token validator for tenant, or nil if the tenant has
// no OAuth AS.
func (r *Resolver) Validator(tenant string) *Server {
	return r.server(tenant)
}

// Handler returns an http.Handler that routes:
//
//	/t/{tenant}/authorize|token|register|jwks.json  → per-tenant AS
//	/t/{tenant}/.well-known/oauth-authorization-server → per-tenant AS metadata
//
// Requests that don't match an OAuth path are passed to the next handler
// (typically the public proxy).
func (r *Resolver) Handler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		// Extract tenant from /t/{tenant}/...
		rest, ok := strings.CutPrefix(req.URL.Path, "/t/")
		if !ok {
			next.ServeHTTP(w, req)
			return
		}
		slash := strings.IndexByte(rest, '/')
		if slash < 0 {
			next.ServeHTTP(w, req)
			return
		}
		tenant := rest[:slash]
		subPath := rest[slash:] // "/authorize", "/token", etc.

		srv := r.server(tenant)
		if srv == nil {
			next.ServeHTTP(w, req)
			return
		}

		// Rewrite the path for the tenant's internal mux.
		req.URL.Path = subPath
		srv.Handler().ServeHTTP(w, req)
	})
}

// WellKnownHandler serves the RFC 8414 and RFC 9728 metadata endpoints that
// live outside /t/{tenant}:
//
//	/.well-known/oauth-authorization-server/t/{tenant}
//	/.well-known/oauth-protected-resource/t/{tenant}/s/{service}
func (r *Resolver) WellKnownHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if !strings.HasPrefix(req.URL.Path, "/.well-known/oauth-") {
			http.NotFound(w, req)
			return
		}
		// Extract tenant from the path suffix:
		// /.well-known/oauth-authorization-server/t/{tenant} → tenant
		// /.well-known/oauth-protected-resource/t/{tenant}/s/{service} → tenant
		parts := strings.SplitN(req.URL.Path, "/t/", 2)
		if len(parts) < 2 {
			http.NotFound(w, req)
			return
		}
		tenantRest := parts[1]
		slash := strings.IndexByte(tenantRest, '/')
		var tenant string
		if slash < 0 {
			tenant = tenantRest
		} else {
			tenant = tenantRest[:slash]
		}

		srv := r.server(tenant)
		if srv == nil {
			http.NotFound(w, req)
			return
		}

		if strings.HasPrefix(req.URL.Path, "/.well-known/oauth-authorization-server") {
			srv.asMetadata(w, req)
		} else {
			srv.resourceMetadata(w, req)
		}
	})
}
