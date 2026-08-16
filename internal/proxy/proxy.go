// Package proxy is the tunneld public router: it forwards requests under
// /t/{tenant}/s/{service}/... over the agent tunnel to the service's
// upstream. Services are bearer-gated by default (OAuth 2.1); services
// created with --no-auth are open — the unguessable quick-tunnel URL is the
// only protection.
package proxy

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/http/httputil"
	"strings"

	"github.com/terragohan/mcptunnels/internal/oauth"
	"github.com/terragohan/mcptunnels/internal/store"
)

// Dialer opens a connection to the agent serving a (tenant, service) pair.
// *gateway.Gateway satisfies it.
type Dialer interface {
	Dial(ctx context.Context, tenant, service string) (net.Conn, error)
}

// maxRequestBody caps request bodies proxied upstream. It sits above the
// bridge's own 4 MiB cap on MCP POST bodies, so legitimate MCP traffic is
// governed by the bridge and only outright abusive uploads hit this one.
const maxRequestBody = 8 << 20 // 8 MiB

// Handler routes /t/{tenant}/s/{service}/* to the named service, preserving
// the path suffix after the service name (e.g. /t/acme/s/demo/mcp → /mcp).
// When the service has auth_mode "oauth" (the default), a valid bearer token
// is required; "open" services skip the check.
type Handler struct {
	dialer   Dialer
	store    *store.Store
	resolver *oauth.Resolver
}

// New returns a Handler dialing services through d and resolving tenants and
// services from st (unknown ones get a 404). resolver may be nil — all
// services are then treated as open.
func New(d Dialer, st *store.Store, resolver *oauth.Resolver) *Handler {
	return &Handler{dialer: d, store: st, resolver: resolver}
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

	// Cap the request body proxied upstream. A known oversized
	// Content-Length is rejected up front with 413; MaxBytesReader covers
	// chunked/unknown-length bodies (those surface as a 502 via the
	// ReverseProxy ErrorHandler when the read fails mid-forward).
	if r.ContentLength > maxRequestBody {
		http.Error(w, "request body too large\n", http.StatusRequestEntityTooLarge)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBody)

	svc, err := h.store.GetService(tenant, service)
	if errors.Is(err, store.ErrNotFound) {
		http.NotFound(w, r)
		return
	}

	// Bearer token enforcement for OAuth-protected services.
	if svc.AuthMode == "oauth" && h.resolver != nil {
		if err := h.authorize(tenant, r); err != nil {
			metadataURL := fmt.Sprintf("%s/.well-known/oauth-protected-resource/t/%s/s/%s",
				h.resolver.BaseURL(), tenant, service)
			w.Header().Set("WWW-Authenticate",
				fmt.Sprintf(`Bearer resource_metadata="%s"`, metadataURL))
			http.Error(w, "unauthorized\n", http.StatusUnauthorized)
			return
		}
	}

	rp := &httputil.ReverseProxy{
		// Responses are deliberately not size-capped: they stream through
		// the yamux stream in HTTP/1.1 wire format, and MCP SSE streams are
		// unbounded by design. Truncating a response mid-stream would hand
		// the client a silently corrupted body — worse than no cap.
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.Out.URL.Scheme = "http"
			pr.Out.URL.Host = "upstream" // ignored: DialContext dials the tunnel
			pr.Out.URL.Path = rest
			pr.Out.URL.RawPath = ""
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

// authorize validates the bearer token on the request against the tenant's
// OAuth AS. It returns nil on success.
func (h *Handler) authorize(tenant string, r *http.Request) error {
	token := strings.TrimSpace(strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "))
	if token == "" {
		return errors.New("missing bearer token")
	}
	validator := h.resolver.Validator(tenant)
	if validator == nil {
		return errors.New("no OAuth AS for tenant")
	}
	_, err := validator.ValidateAccessToken(token)
	return err
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
