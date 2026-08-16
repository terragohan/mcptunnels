package oauth

import (
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/generalpiston/openai-tunnel-oauth/internal/config"
	"github.com/generalpiston/openai-tunnel-oauth/internal/idp"
	"github.com/generalpiston/openai-tunnel-oauth/internal/store"
)

// ResolverConfig configures the per-tenant AS resolver.
type ResolverConfig struct {
	// BaseURL is tunneld's public base URL, e.g. https://tunnel.example.com
	// (no trailing slash). Tenant issuers are BaseURL + "/t/" + slug.
	BaseURL string
	Store   *store.Store

	// DevUsername / DevPassword are the dev-login fallback for tenants with
	// no IdP configured. Empty password disables the dev login.
	DevUsername string
	DevPassword string

	AllowedRedirectHosts []string

	RegisterRatePerMin int
	TokenRatePerMin    int

	AccessTokenTTL  time.Duration
	RefreshTokenTTL time.Duration

	Scopes []string
}

// Resolver builds and caches a tenant-scoped authorization server per tenant
// slug, and routes the public per-tenant endpoints (/t/{tenant}/...) plus the
// RFC 8414 / RFC 9728 well-known documents.
//
// Servers are cached until Invalidate is called (the control plane does this
// on idp set/delete and keys rotate).
type Resolver struct {
	cfg ResolverConfig

	mu      sync.Mutex
	servers map[string]*Server
}

// NewResolver builds a Resolver.
func NewResolver(cfg ResolverConfig) *Resolver {
	return &Resolver{cfg: cfg, servers: make(map[string]*Server)}
}

// validSlug mirrors the control plane's slug rules.
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

// resolve returns the tenant's AS, building and caching it on first use. It
// returns store.ErrNotFound for unknown or disabled tenants.
func (r *Resolver) resolve(tenant string) (*Server, error) {
	if !validSlug(tenant) {
		return nil, store.ErrNotFound
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if srv, ok := r.servers[tenant]; ok {
		return srv, nil
	}
	t, err := r.cfg.Store.GetTenant(tenant)
	if err != nil {
		return nil, err
	}
	if t.DisabledAt != nil {
		return nil, store.ErrNotFound
	}
	idpCfgs, err := r.cfg.Store.ListIDP(tenant)
	if err != nil {
		return nil, err
	}
	providers := make([]config.IdPProvider, 0, len(idpCfgs))
	for _, c := range idpCfgs {
		providers = append(providers, config.IdPProvider{
			Name:           c.Name,
			ClientID:       c.ClientID,
			ClientSecret:   c.ClientSecret,
			Issuer:         c.Issuer,
			AllowedEmails:  c.AllowedEmails,
			AllowedDomains: c.AllowedDomains,
		})
	}
	srv, err := NewServer(Config{
		Issuer:               strings.TrimRight(r.cfg.BaseURL, "/") + "/t/" + tenant,
		Store:                r.cfg.Store,
		TenantSlug:           tenant,
		DevUsername:          r.cfg.DevUsername,
		DevPassword:          r.cfg.DevPassword,
		Broker:               idp.NewBroker(providers),
		AllowedRedirectHosts: r.cfg.AllowedRedirectHosts,
		RegisterRatePerMin:   r.cfg.RegisterRatePerMin,
		TokenRatePerMin:      r.cfg.TokenRatePerMin,
		AccessTokenTTL:       r.cfg.AccessTokenTTL,
		RefreshTokenTTL:      r.cfg.RefreshTokenTTL,
		Scopes:               r.cfg.Scopes,
	})
	if err != nil {
		return nil, err
	}
	r.servers[tenant] = srv
	return srv, nil
}

// Invalidate drops the cached AS for a tenant, so the next request rebuilds
// it from the store (signing keys, IdP configs). Called by the control plane
// after `idp set/delete` and `keys rotate`.
func (r *Resolver) Invalidate(tenant string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.servers, tenant)
}

// Validator returns the tenant's access-token validator for the MCP proxy.
// The second return value reports whether the tenant exists.
func (r *Resolver) Validator(tenant string) (*Server, bool) {
	srv, err := r.resolve(tenant)
	if err != nil {
		return nil, false
	}
	return srv, true
}

// Handler returns the public mux: per-tenant AS endpoints under /t/{tenant}
// plus the well-known metadata documents.
func (r *Resolver) Handler() http.Handler {
	mux := http.NewServeMux()

	tenantAS := func(w http.ResponseWriter, req *http.Request) {
		tenant := req.PathValue("tenant")
		srv, err := r.resolve(tenant)
		if err != nil {
			http.NotFound(w, req)
			return
		}
		// The Server's mux is rooted at the tenant prefix; strip it.
		http.StripPrefix("/t/"+tenant, srv.Handler()).ServeHTTP(w, req)
	}
	for _, p := range []string{
		"GET /t/{tenant}/authorize",
		"POST /t/{tenant}/authorize",
		"POST /t/{tenant}/authorize/consent",
		"POST /t/{tenant}/token",
		"POST /t/{tenant}/register",
		"GET /t/{tenant}/jwks.json",
		"GET /t/{tenant}/idp/{name}/login",
		"GET /t/{tenant}/idp/{name}/callback",
	} {
		mux.HandleFunc(p, tenantAS)
	}

	// RFC 8414 AS metadata. Path form: issuer is BaseURL + /t/{tenant}, so
	// the document lives at /.well-known/oauth-authorization-server/t/{tenant}.
	mux.HandleFunc("GET /.well-known/oauth-authorization-server/t/{tenant}", func(w http.ResponseWriter, req *http.Request) {
		srv, err := r.resolve(req.PathValue("tenant"))
		if err != nil {
			http.NotFound(w, req)
			return
		}
		srv.handleMetadata(w, req)
	})
	// Root form (permissive fallback): serve the default tenant's document.
	mux.HandleFunc("GET /.well-known/oauth-authorization-server", func(w http.ResponseWriter, req *http.Request) {
		srv, err := r.resolve(store.DefaultTenantSlug)
		if err != nil {
			http.NotFound(w, req)
			return
		}
		srv.handleMetadata(w, req)
	})

	// RFC 9728 protected-resource metadata. Path form carries the resource
	// path as a suffix: /.well-known/oauth-protected-resource/t/{tenant}/s/{service}.
	mux.HandleFunc("GET /.well-known/oauth-protected-resource", func(w http.ResponseWriter, req *http.Request) {
		r.serveProtectedResource(w, req, "")
	})
	mux.HandleFunc("GET /.well-known/oauth-protected-resource/", func(w http.ResponseWriter, req *http.Request) {
		suffix := strings.TrimPrefix(req.URL.Path, "/.well-known/oauth-protected-resource")
		r.serveProtectedResource(w, req, suffix)
	})
	return mux
}

// serveProtectedResource renders the RFC 9728 document. suffix is the
// resource path ("" for the root form, or "/t/{tenant}/s/{service}[/...]").
func (r *Resolver) serveProtectedResource(w http.ResponseWriter, req *http.Request, suffix string) {
	base := strings.TrimRight(r.cfg.BaseURL, "/")
	tenant := store.DefaultTenantSlug
	if suffix != "" {
		rest, ok := strings.CutPrefix(suffix, "/t/")
		if !ok {
			http.NotFound(w, req)
			return
		}
		if i := strings.IndexByte(rest, '/'); i >= 0 {
			tenant = rest[:i]
		} else {
			tenant = rest
		}
	}
	srv, err := r.resolve(tenant)
	if err != nil {
		http.NotFound(w, req)
		return
	}
	resource := base + suffix
	writeJSON(w, http.StatusOK, protectedResourceDoc{
		Resource:             resource,
		AuthorizationServers: []string{srv.issuer},
	})
}
