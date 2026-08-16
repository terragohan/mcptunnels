// Package gateway implements the tunneld side of the tunnel: it accepts agent
// WebSocket connections on /tunnel/connect, runs a yamux client session over
// each, and hands out yamux streams as net.Conns to the public proxy.
package gateway

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync"

	"github.com/coder/websocket"
	"github.com/hashicorp/yamux"

	"github.com/terragohan/mcptunnels/internal/store"
	"github.com/terragohan/mcptunnels/internal/tunnelproto"
)

// ErrServiceOffline is returned by Dial when no agent tunnel is currently
// connected for the requested (tenant, service) pair.
var ErrServiceOffline = errors.New("gateway: service offline")

// Gateway accepts agent connections and dispenses streams to them. It is safe
// for concurrent use.
type Gateway struct {
	st *store.Store

	mu       sync.Mutex
	sessions map[string]*yamux.Session // tenant + "\x00" + service -> active session
}

// New returns a Gateway that authorizes agents against the store:
// Authorization: Bearer <agent_key> is checked with
// store.ValidateAgentKey(X-Tenant, X-Service-Name, key).
func New(st *store.Store) *Gateway {
	return &Gateway{
		st:       st,
		sessions: make(map[string]*yamux.Session),
	}
}

func sessionKey(tenant, service string) string { return tenant + "\x00" + service }

// ServeHTTP handles agent connections on tunnelproto.ConnectPath.
func (g *Gateway) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	tenant := r.Header.Get(tunnelproto.HeaderTenant)
	service := r.Header.Get(tunnelproto.HeaderServiceName)
	key := strings.TrimSpace(strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "))
	if tenant == "" || service == "" {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	if _, err := g.st.ValidateAgentKey(tenant, service, key); err != nil {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	ws, err := websocket.Accept(w, r, &websocket.AcceptOptions{
		// Agents are not browsers; there is no Origin header to check.
		InsecureSkipVerify: true,
	})
	if err != nil {
		slog.Warn("gateway: websocket accept failed", "tenant", tenant, "service", service, "err", err)
		return
	}

	conn := websocket.NetConn(r.Context(), ws, websocket.MessageBinary)
	sess, err := yamux.Client(conn, nil)
	if err != nil {
		conn.Close()
		slog.Warn("gateway: yamux client failed", "tenant", tenant, "service", service, "err", err)
		return
	}
	sk := sessionKey(tenant, service)
	g.register(sk, sess)
	slog.Info("gateway: agent connected", "tenant", tenant, "service", service, "remote", r.RemoteAddr)

	// Block until the tunnel dies; the request context then closes the
	// WebSocket, and we drop the session from the registry.
	<-sess.CloseChan()
	g.unregister(sk, sess)
	slog.Info("gateway: agent disconnected", "tenant", tenant, "service", service)
}

// Dial returns a connection to the agent currently serving the (tenant,
// service) pair. The returned conn is a yamux stream; write one HTTP request
// to it and read one HTTP response back.
func (g *Gateway) Dial(_ context.Context, tenant, service string) (net.Conn, error) {
	g.mu.Lock()
	sess := g.sessions[sessionKey(tenant, service)]
	g.mu.Unlock()
	if sess == nil {
		return nil, ErrServiceOffline
	}
	stream, err := sess.Open()
	if err != nil {
		return nil, ErrServiceOffline
	}
	return stream, nil
}

// Online reports whether an agent tunnel is currently registered for the
// (tenant, service) pair.
func (g *Gateway) Online(tenant, service string) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	_, ok := g.sessions[sessionKey(tenant, service)]
	return ok
}

// register stores sess for key, replacing (and closing) any previous
// session — a reconnecting agent takes over from its stale predecessor.
func (g *Gateway) register(key string, sess *yamux.Session) {
	g.mu.Lock()
	old := g.sessions[key]
	g.sessions[key] = sess
	g.mu.Unlock()
	if old != nil {
		old.Close()
	}
}

// unregister drops sess only if it is still the registered session, so a
// dying old session cannot evict its replacement.
func (g *Gateway) unregister(key string, sess *yamux.Session) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.sessions[key] == sess {
		delete(g.sessions, key)
	}
}
