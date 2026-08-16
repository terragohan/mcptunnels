package controlplane_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/terragohan/mcptunnels/internal/controlplane"
	"github.com/terragohan/mcptunnels/internal/store"
	"github.com/terragohan/mcptunnels/internal/store/storetest"
)

// api is a small test client for the control-plane handler.
type api struct {
	t    *testing.T
	base string
}

func newAPI(t *testing.T, st *store.Store) *api {
	t.Helper()
	srv := httptest.NewServer(controlplane.New(st).Handler())
	t.Cleanup(srv.Close)
	return &api{t: t, base: srv.URL}
}

func (a *api) do(method, path string, body, out any) int {
	a.t.Helper()
	var rdr *bytes.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			a.t.Fatal(err)
		}
		rdr = bytes.NewReader(data)
	} else {
		rdr = bytes.NewReader(nil)
	}
	req, err := http.NewRequest(method, a.base+"/api/v1"+path, rdr)
	if err != nil {
		a.t.Fatal(err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		a.t.Fatal(err)
	}
	defer resp.Body.Close()
	if out != nil {
		if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
			a.t.Fatalf("decode %s %s: %v", method, path, err)
		}
	}
	return resp.StatusCode
}

// quickBody is the JSON body for a POST /quick that creates an OAuth-protected
// tunnel with the given password.
func quickBody(password string) map[string]any {
	return map[string]any{"auth": true, "password": password}
}

// quickBodyNoAuth creates an open (unauthenticated) tunnel.
func quickBodyNoAuth() map[string]any {
	return map[string]any{"auth": false}
}

// TestQuickTunnel exercises POST /api/v1/quick: it creates an ephemeral
// tenant with a random slug plus an OAuth-protected service, and returns the
// agent key.
func TestQuickTunnel(t *testing.T) {
	st := storetest.Open(t)
	a := newAPI(t, st)

	var resp struct {
		Tenant    string `json:"tenant"`
		Service   string `json:"service"`
		AgentKey  string `json:"agent_key"`
		ExpiresAt int64  `json:"expires_at"`
	}
	if code := a.do("POST", "/quick", quickBody("testpass"), &resp); code != http.StatusCreated {
		t.Fatalf("quick: status %d, want 201", code)
	}
	if !strings.HasPrefix(resp.Tenant, "q-") || len(resp.Tenant) != 12 {
		t.Fatalf("tenant slug = %q, want q-<10 chars>", resp.Tenant)
	}
	if resp.Service != "mcp" {
		t.Fatalf("service = %q, want mcp", resp.Service)
	}
	if !strings.HasPrefix(resp.AgentKey, "tun_agent_") {
		t.Fatalf("agent_key = %q, want tun_agent_ prefix", resp.AgentKey)
	}
	if d := time.Until(time.Unix(resp.ExpiresAt, 0)); d < 23*time.Hour || d > 24*time.Hour {
		t.Fatalf("expires_at is %v from now, want ~24h", d)
	}

	// The tenant exists, is marked ephemeral, and holds the service; the
	// returned agent key validates.
	tn, err := st.GetTenant(resp.Tenant)
	if err != nil {
		t.Fatal(err)
	}
	if tn.DisplayName != "quick tunnel" || tn.ExpiresAt == nil || tn.ExpiresAt.Unix() != resp.ExpiresAt {
		t.Fatalf("tenant = %+v, want display name %q and expires_at %d", tn, "quick tunnel", resp.ExpiresAt)
	}
	if _, err := st.ValidateAgentKey(resp.Tenant, "mcp", resp.AgentKey); err != nil {
		t.Fatalf("ValidateAgentKey: %v", err)
	}

	// Slugs are unique across calls.
	var resp2 struct {
		Tenant string `json:"tenant"`
	}
	if code := a.do("POST", "/quick", quickBody("testpass"), &resp2); code != http.StatusCreated {
		t.Fatalf("quick #2: status %d, want 201", code)
	}
	if resp2.Tenant == resp.Tenant {
		t.Fatal("two quick tunnels got the same slug")
	}
}

// TestQuickTunnelRateLimit verifies the per-IP cap (10/hour): the 11th
// request from the same remote IP gets a 429.
func TestQuickTunnelRateLimit(t *testing.T) {
	st := storetest.Open(t)
	a := newAPI(t, st)
	for i := range 10 {
		if code := a.do("POST", "/quick", quickBody("testpass"), nil); code != http.StatusCreated {
			t.Fatalf("quick #%d: status %d, want 201", i+1, code)
		}
	}
	if code := a.do("POST", "/quick", quickBody("testpass"), nil); code != http.StatusTooManyRequests {
		t.Fatalf("quick #11: status %d, want 429", code)
	}
}

// TestQuickTunnelRateLimitSurvivesRestart verifies the per-IP cap is
// persisted: a "restarted" control plane against the same database still
// rejects the 11th request from the same remote IP.
func TestQuickTunnelRateLimitSurvivesRestart(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "test.db")

	st1, err := store.Open(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	a1 := newAPI(t, st1)
	for i := range 10 {
		if code := a1.do("POST", "/quick", quickBody("testpass"), nil); code != http.StatusCreated {
			t.Fatalf("quick #%d: status %d, want 201", i+1, code)
		}
	}

	// "Restart": close the store and reopen a fresh control plane on the
	// same database file.
	if err := st1.Close(); err != nil {
		t.Fatal(err)
	}
	st2, err := store.Open(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st2.Close() })
	a2 := newAPI(t, st2)

	if code := a2.do("POST", "/quick", quickBody("testpass"), nil); code != http.StatusTooManyRequests {
		t.Fatalf("quick #11 after restart: status %d, want 429", code)
	}
}

// TestQuickTunnelCapacity verifies POST /quick returns 503 once
// maxLiveTunnels (500) non-expired tenants exist. The tenants are inserted
// directly into the store — going through the endpoint would hit the per-IP
// rate limit long before the cap.
func TestQuickTunnelCapacity(t *testing.T) {
	st := storetest.Open(t)
	expires := time.Now().Add(time.Hour)
	for i := range 500 {
		if err := st.CreateTenantExpiry(fmt.Sprintf("q-%010d", i), "quick tunnel", &expires); err != nil {
			t.Fatal(err)
		}
	}
	a := newAPI(t, st)
	if code := a.do("POST", "/quick", quickBody("testpass"), nil); code != http.StatusServiceUnavailable {
		t.Fatalf("quick at capacity: status %d, want 503", code)
	}
}

// TestExpiredQuickTunnelGone verifies a quick tunnel whose TTL has passed is
// swept by DeleteExpiredTenants and its service stops validating.
func TestExpiredQuickTunnelGone(t *testing.T) {
	st := storetest.Open(t)
	a := newAPI(t, st)

	var resp struct {
		Tenant   string `json:"tenant"`
		AgentKey string `json:"agent_key"`
	}
	if code := a.do("POST", "/quick", quickBody("testpass"), &resp); code != http.StatusCreated {
		t.Fatalf("quick: status %d, want 201", code)
	}
	slugs, err := st.DeleteExpiredTenants(time.Now().Add(controlplane.QuickTTL + time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if len(slugs) != 1 || slugs[0] != resp.Tenant {
		t.Fatalf("swept slugs = %v, want [%s]", slugs, resp.Tenant)
	}
	if _, err := st.ValidateAgentKey(resp.Tenant, "mcp", resp.AgentKey); err == nil {
		t.Fatal("agent key still valid after the tenant expired")
	}
}

// TestQuickTunnelRequiresPassword verifies that POST /quick with auth=true
// (the default) but no password returns 400.
func TestQuickTunnelRequiresPassword(t *testing.T) {
	st := storetest.Open(t)
	a := newAPI(t, st)
	if code := a.do("POST", "/quick", map[string]any{"auth": true}, nil); code != http.StatusBadRequest {
		t.Fatalf("auth without password: status %d, want 400", code)
	}
	// Empty body also defaults to auth=true.
	if code := a.do("POST", "/quick", nil, nil); code != http.StatusBadRequest {
		t.Fatalf("empty body: status %d, want 400", code)
	}
}

// TestQuickTunnelNoAuth verifies that auth=false creates an open service.
func TestQuickTunnelNoAuth(t *testing.T) {
	st := storetest.Open(t)
	a := newAPI(t, st)
	var resp struct {
		Tenant string `json:"tenant"`
	}
	if code := a.do("POST", "/quick", quickBodyNoAuth(), &resp); code != http.StatusCreated {
		t.Fatalf("quick no-auth: status %d, want 201", code)
	}
	svc, err := st.GetService(resp.Tenant, "mcp")
	if err != nil {
		t.Fatal(err)
	}
	if svc.AuthMode != "open" {
		t.Fatalf("auth_mode = %q, want %q", svc.AuthMode, "open")
	}
	if svc.PasswordHash != "" {
		t.Fatal("open service should not have a password")
	}
}

// TestDeleteQuickTunnel verifies DELETE /api/v1/quick/{tenant} destroys the
// tunnel when authenticated with the agent key.
func TestDeleteQuickTunnel(t *testing.T) {
	st := storetest.Open(t)
	a := newAPI(t, st)

	var resp struct {
		Tenant   string `json:"tenant"`
		AgentKey string `json:"agent_key"`
	}
	if code := a.do("POST", "/quick", quickBody("testpass"), &resp); code != http.StatusCreated {
		t.Fatalf("quick: status %d, want 201", code)
	}

	// Without auth headers → 401.
	if code := a.do("DELETE", "/quick/"+resp.Tenant, nil, nil); code != http.StatusUnauthorized {
		t.Fatalf("delete without auth: status %d, want 401", code)
	}

	// With wrong key → 401.
	req, _ := http.NewRequest("DELETE", a.base+"/api/v1/quick/"+resp.Tenant, nil)
	req.Header.Set("Authorization", "Bearer wrong-key")
	req.Header.Set("X-Service-Name", "mcp")
	delResp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	delResp.Body.Close()
	if delResp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("delete with wrong key: status %d, want 401", delResp.StatusCode)
	}

	// With correct key → 204.
	req, _ = http.NewRequest("DELETE", a.base+"/api/v1/quick/"+resp.Tenant, nil)
	req.Header.Set("Authorization", "Bearer "+resp.AgentKey)
	req.Header.Set("X-Service-Name", "mcp")
	delResp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	delResp.Body.Close()
	if delResp.StatusCode != http.StatusNoContent {
		t.Fatalf("delete: status %d, want 204", delResp.StatusCode)
	}

	// Tenant is gone.
	if _, err := st.GetTenant(resp.Tenant); err == nil {
		t.Fatal("tenant still exists after delete")
	}

	// Second delete → 404.
	req, _ = http.NewRequest("DELETE", a.base+"/api/v1/quick/"+resp.Tenant, nil)
	req.Header.Set("Authorization", "Bearer "+resp.AgentKey)
	req.Header.Set("X-Service-Name", "mcp")
	delResp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	delResp.Body.Close()
	if delResp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("delete after delete: status %d, want 401 (agent key dead)", delResp.StatusCode)
	}
}
