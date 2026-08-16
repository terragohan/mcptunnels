package proxy_test

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/terragohan/mcptunnels/internal/oauth"
	"github.com/terragohan/mcptunnels/internal/proxy"
	"github.com/terragohan/mcptunnels/internal/store"
	"github.com/terragohan/mcptunnels/internal/store/storetest"
)

// offlineDialer always fails — simulates no connected agent.
type offlineDialer struct{}

func (d *offlineDialer) Dial(_ context.Context, _, _ string) (net.Conn, error) {
	return nil, fmt.Errorf("no agent connected")
}

// setupAuthProxy creates a store with a tenant + service in the given
// auth_mode, an OAuth resolver, and a proxy handler.
func setupAuthProxy(t *testing.T, authMode string) *httptest.Server {
	t.Helper()
	st := storetest.Open(t)
	expires := time.Now().Add(time.Hour)
	if err := st.CreateTenantExpiry("q-auth", "quick tunnel", &expires); err != nil {
		t.Fatal(err)
	}
	if _, err := st.CreateService("q-auth", &store.Service{Name: "mcp", AuthMode: authMode}); err != nil {
		t.Fatal(err)
	}
	if authMode == "oauth" {
		pemStr, err := oauth.GenerateKey()
		if err != nil {
			t.Fatal(err)
		}
		if err := st.CreateSigningKey("q-auth", pemStr); err != nil {
			t.Fatal(err)
		}
	}
	resolver := oauth.NewResolver(st, "http://localhost")
	srv := httptest.NewServer(proxy.New(&offlineDialer{}, st, resolver))
	t.Cleanup(srv.Close)
	return srv
}

// TestProxyOAuthRequired verifies that an OAuth-protected service rejects
// requests without a bearer token.
func TestProxyOAuthRequired(t *testing.T) {
	srv := setupAuthProxy(t, "oauth")
	resp, err := http.Post(srv.URL+"/t/q-auth/s/mcp", "application/json", strings.NewReader("{}"))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("no token: status %d, want 401", resp.StatusCode)
	}
	if wa := resp.Header.Get("WWW-Authenticate"); !strings.Contains(wa, "resource_metadata") {
		t.Fatalf("WWW-Authenticate %q missing resource_metadata", wa)
	}
}

// TestProxyOAuthRejectsBadToken verifies that an invalid bearer token is
// rejected.
func TestProxyOAuthRejectsBadToken(t *testing.T) {
	srv := setupAuthProxy(t, "oauth")
	req, _ := http.NewRequest("POST", srv.URL+"/t/q-auth/s/mcp", strings.NewReader("{}"))
	req.Header.Set("Authorization", "Bearer invalid.token.here")
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("bad token: status %d, want 401", resp.StatusCode)
	}
}

// TestProxyOpenServiceNoAuth verifies that an "open" service skips the bearer
// check entirely. The dialer fails (no agent), so we get 502 — the point is
// that we got past auth.
func TestProxyOpenServiceNoAuth(t *testing.T) {
	srv := setupAuthProxy(t, "open")
	resp, err := http.Post(srv.URL+"/t/q-auth/s/mcp", "application/json", strings.NewReader("{}"))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("open service: status %d, want 502 (auth passed, agent offline)", resp.StatusCode)
	}
}
