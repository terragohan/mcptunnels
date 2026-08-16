// Package proxy is the tunneld public router: it forwards requests under
// /t/{tenant}/s/{service}/... over the agent tunnel to the service's
// upstream. Services are unauthenticated ("open"): the unguessable
// quick-tunnel URL is the only protection.
package proxy

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"net/http/httputil"
	"strings"

	"github.com/generalpiston/openai-tunnel-oauth/internal/store"
)

// Dialer opens a connection to the agent serving a (tenant, service) pair.
// *gateway.Gateway satisfies it.
type Dialer interface {
	Dial(ctx context.Context, tenant, service string) (net.Conn, error)
}

// Handler routes /t/{tenant}/s/{service}/* to the named service, preserving
// the path suffix after the service name (e.g. /t/acme/s/demo/mcp → /mcp).
type Handler struct {
	dialer Dialer
	store  *store.Store
}

// New returns a Handler dialing services through d and resolving tenants and
// services from st (unknown ones get a 404).
func New(d Dialer, st *store.Store) *Handler {
	return &Handler{dialer: d, store: st}
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

	if _, err := h.store.GetService(tenant, service); errors.Is(err, store.ErrNotFound) {
		http.NotFound(w, r)
		return
	}

	rp := &httputil.ReverseProxy{
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
