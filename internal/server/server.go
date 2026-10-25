// Package server composes the full tunneld HTTP handler: gateway, control
// plane, OAuth authorization server + discovery metadata, and the public
// reverse proxy. cmd/tunneld wires this to a listener; tests serve it
// in-process.
package server

import (
	"net/http"

	"github.com/terragohan/mcptunnels/internal/controlplane"
	"github.com/terragohan/mcptunnels/internal/gateway"
	"github.com/terragohan/mcptunnels/internal/oauth"
	"github.com/terragohan/mcptunnels/internal/proxy"
	"github.com/terragohan/mcptunnels/internal/store"
	"github.com/terragohan/mcptunnels/internal/tunnelproto"
)

// NewHandler builds the complete tunneld handler for one store and public
// base URL (e.g. https://tunnel.example.com). PublicBaseURL feeds the OAuth
// discovery metadata, so for in-process tests bind the listener first and
// pass the real reachable base.
func NewHandler(st *store.Store, publicBaseURL string) (http.Handler, *gateway.Gateway) {
	// Agents authenticate with the agent key returned by POST /api/v1/quick
	// plus X-Tenant / X-Service-Name headers.
	gw := gateway.New(st)
	cp := controlplane.New(st)
	resolver := oauth.NewResolver(st, publicBaseURL)

	mux := http.NewServeMux()
	mux.Handle(tunnelproto.ConnectPath, gw)
	mux.Handle("/api/v1/", cp.Handler())
	mux.Handle("/t/{tenant}/s/", proxy.New(gw, st, resolver))
	mux.Handle("/.well-known/", resolver.WellKnownHandler())
	mux.Handle("/t/", resolver.Handler(http.NotFoundHandler()))
	mux.HandleFunc("GET /healthz", proxy.Healthz)
	return mux, gw
}
