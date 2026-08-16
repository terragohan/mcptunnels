// Package proxy is the tunneld public router: it forwards requests under
// /t/{tenant}/s/{service}/... over the agent tunnel to the service's
// upstream, gating them on a valid tenant-scoped OAuth bearer token, and
// injecting signed identity headers for the backend.
package proxy

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httputil"
	"strings"

	"github.com/generalpiston/openai-tunnel-oauth/internal/oauth"
	"github.com/generalpiston/openai-tunnel-oauth/internal/store"
)

// Dialer opens a connection to the agent serving a (tenant, service) pair.
// *gateway.Gateway satisfies it.
type Dialer interface {
	Dial(ctx context.Context, tenant, service string) (net.Conn, error)
}

// Validator validates an access token. *oauth.Server satisfies it.
type Validator interface {
	ValidateAccessToken(token string) (*oauth.AccessClaims, error)
}

// Per-service auth modes (stored on services.auth_mode).
const (
	AuthModeStrict        = "strict"
	AuthModeDiscoveryOpen = "discovery_open"
)

// Auth configures bearer-token enforcement on proxied routes.
type Auth struct {
	// BaseURL is tunneld's public base URL, e.g. https://tunnel.example.com
	// (no trailing slash). Tenant issuers are BaseURL + "/t/" + slug.
	BaseURL string
	// ValidatorFor resolves the token validator for a tenant; it reports
	// false for unknown tenants. *oauth.Resolver provides this.
	ValidatorFor func(tenant string) (Validator, bool)
	// Store provides per-service settings (auth_mode, identity_secret).
	Store *store.Store
}

// Handler routes /t/{tenant}/s/{service}/* to the named service, preserving
// the path suffix after the service name (e.g. /t/acme/s/demo/mcp → /mcp).
type Handler struct {
	dialer Dialer
	auth   *Auth
}

// New returns a Handler dialing services through d, gated by auth (may be
// nil for no auth — tests only).
func New(d Dialer, auth *Auth) *Handler {
	return &Handler{dialer: d, auth: auth}
}

// Healthz is a plain liveness endpoint; it does not touch any tunnel.
func Healthz(w http.ResponseWriter, _ *http.Request) {
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("ok\n"))
}

// ServeHTTP implements http.Handler.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	tenant, service, rest := splitPath(r.URL.Path)
	if tenant == "" || service == "" {
		http.NotFound(w, r)
		return
	}

	claims, ok := h.authorized(w, r, tenant, service, rest)
	if !ok {
		return
	}

	identitySecret := ""
	if h.auth != nil && h.auth.Store != nil {
		if svc, err := h.auth.Store.GetService(tenant, service); err == nil {
			identitySecret = svc.IdentitySecret
		}
	}

	rp := &httputil.ReverseProxy{
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.Out.URL.Scheme = "http"
			pr.Out.URL.Host = "upstream" // ignored: DialContext dials the tunnel
			pr.Out.URL.Path = rest
			pr.Out.URL.RawPath = ""
			if claims != nil && identitySecret != "" {
				injectIdentityHeaders(pr.Out.Header, claims, identitySecret)
			}
		},
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				return h.dialer.Dial(ctx, tenant, service)
			},
			// Do not negotiate gzip with the upstream: it would buffer
			// streamed (SSE) responses.
			DisableCompression: true,
		},
		ErrorHandler: func(w http.ResponseWriter, _ *http.Request, err error) {
			slog.Warn("proxy: upstream dial failed", "tenant", tenant, "service", service, "err", err)
			http.Error(w, "bad gateway: service offline\n", http.StatusBadGateway)
		},
	}
	rp.ServeHTTP(w, r)
}

// authorized enforces access. It returns the validated claims (nil for an
// unauthenticated-but-allowed discovery_open request) and whether the
// request may proceed. On failure it writes the response itself, with the
// RFC 9728 WWW-Authenticate challenge on 401s.
func (h *Handler) authorized(w http.ResponseWriter, r *http.Request, tenant, service, rest string) (*oauth.AccessClaims, bool) {
	if h.auth == nil || h.auth.ValidatorFor == nil {
		return nil, true
	}

	tenantIssuer := strings.TrimRight(h.auth.BaseURL, "/") + "/t/" + tenant

	validator, ok := h.auth.ValidatorFor(tenant)
	if !ok {
		http.NotFound(w, r)
		return nil, false
	}

	authMode := AuthModeStrict
	if h.auth.Store != nil {
		svc, err := h.auth.Store.GetService(tenant, service)
		if errors.Is(err, store.ErrNotFound) {
			http.NotFound(w, r)
			return nil, false
		}
		if err == nil {
			authMode = svc.AuthMode
		}
	}

	token, _ := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	claims, err := validator.ValidateAccessToken(token)
	if err == nil && audienceMatches(claims, tenantIssuer, strings.TrimRight(h.auth.BaseURL, "/")+r.URL.Path) {
		return claims, true
	}

	if authMode == AuthModeDiscoveryOpen && discoveryOpenAllowed(r, rest) {
		// Unauthenticated discovery request: never forward identity headers.
		return nil, true
	}

	base := strings.TrimRight(h.auth.BaseURL, "/")
	w.Header().Set("WWW-Authenticate", fmt.Sprintf(
		`Bearer realm=%q, resource_metadata=%q`,
		tenantIssuer,
		base+"/.well-known/oauth-protected-resource/t/"+tenant+"/s/"+service,
	))
	http.Error(w, "unauthorized\n", http.StatusUnauthorized)
	return nil, false
}

// discoveryMethods are the MCP methods callable without a token in
// discovery_open mode.
var discoveryMethods = map[string]bool{
	"initialize": true,
	"ping":       true,
	"tools/list": true,
}

// discoveryOpenAllowed reports whether an unauthenticated request qualifies
// under discovery_open mode: it must target /mcp, and
//   - GET is allowed: after initialize, the Streamable HTTP SSE stream is a
//     GET on the same endpoint, and the (unauthenticated) scanner needs it.
//   - POST must carry a single (non-batch) JSON-RPC message whose method is
//     initialize, ping, or tools/list.
//
// The POST body is consumed and restored for the upstream.
func discoveryOpenAllowed(r *http.Request, rest string) bool {
	if rest != "/mcp" {
		return false
	}
	switch r.Method {
	case http.MethodGet:
		return true
	case http.MethodPost:
		body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
		r.Body.Close()
		if err != nil {
			return false
		}
		r.Body = io.NopCloser(bytes.NewReader(body))
		return rpcMethodAllowed(body)
	default:
		return false
	}
}

// rpcMethodAllowed reports whether body is a single JSON-RPC message (batch
// arrays and invalid JSON are rejected) with an allowed discovery method.
func rpcMethodAllowed(body []byte) bool {
	var msg struct {
		Method string `json:"method"`
	}
	if err := json.Unmarshal(body, &msg); err != nil {
		return false
	}
	return discoveryMethods[msg.Method]
}

// audienceMatches accepts a token when its audience is the tenant issuer
// itself or a path prefix of the request URL (e.g. aud
// https://host/t/acme/s/demo covers reqURL https://host/t/acme/s/demo/mcp).
func audienceMatches(claims *oauth.AccessClaims, tenantIssuer, reqURL string) bool {
	if claims == nil {
		return false
	}
	for _, aud := range claims.Audience {
		if aud == tenantIssuer || strings.HasPrefix(reqURL, aud) {
			return true
		}
	}
	return false
}

// Identity headers injected into authenticated tunneled requests.
const (
	HeaderAuthSubject   = "X-Auth-Subject"
	HeaderAuthEmail     = "X-Auth-Email"
	HeaderAuthScopes    = "X-Auth-Scopes"
	HeaderAuthClientID  = "X-Auth-Client-Id"
	HeaderAuthSignature = "X-Auth-Signature"
)

// injectIdentityHeaders sets the X-Auth-* headers for the validated claims,
// including the HMAC-SHA256 signature over
// "{subject}\n{email}\n{scopes}\n{client_id}" with the service's
// identity_secret.
func injectIdentityHeaders(h http.Header, claims *oauth.AccessClaims, secret string) {
	h.Set(HeaderAuthSubject, claims.Subject)
	h.Set(HeaderAuthEmail, claims.Email)
	h.Set(HeaderAuthScopes, claims.Scope)
	h.Set(HeaderAuthClientID, claims.ClientID)
	h.Set(HeaderAuthSignature, SignIdentity(secret, claims.Subject, claims.Email, claims.Scope, claims.ClientID))
}

// SignIdentity computes the X-Auth-Signature value. Exported so backends and
// tests can verify provenance with the shared per-service secret.
func SignIdentity(secret, subject, email, scopes, clientID string) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(subject + "\n" + email + "\n" + scopes + "\n" + clientID))
	return hex.EncodeToString(mac.Sum(nil))
}

// splitPath splits "/t/{tenant}/s/{service}/rest/of/path" into ("{tenant}",
// "{service}", "/rest/of/path"). "/t/{tenant}/s/{service}" maps to rest "/".
// Anything not under /t/{tenant}/s/ yields empty tenant/service.
func splitPath(path string) (tenant, service, rest string) {
	p, ok := strings.CutPrefix(path, "/t/")
	if !ok {
		return "", "", ""
	}
	i := strings.IndexByte(p, '/')
	if i < 0 {
		return "", "", ""
	}
	tenant = p[:i]
	sp, ok := strings.CutPrefix(p[i:], "/s/")
	if !ok {
		return "", "", ""
	}
	if j := strings.IndexByte(sp, '/'); j >= 0 {
		return tenant, sp[:j], sp[j:]
	}
	return tenant, sp, "/"
}
