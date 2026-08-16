package controlplane_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/generalpiston/mcptunnels/internal/controlplane"
	"github.com/generalpiston/mcptunnels/internal/store"
	"github.com/generalpiston/mcptunnels/internal/store/storetest"
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

// TestQuickTunnel exercises POST /api/v1/quick: it creates an ephemeral
// tenant with a random slug plus an open service, and returns the agent key.
func TestQuickTunnel(t *testing.T) {
	st := storetest.Open(t)
	a := newAPI(t, st)

	var resp struct {
		Tenant    string `json:"tenant"`
		Service   string `json:"service"`
		AgentKey  string `json:"agent_key"`
		ExpiresAt int64  `json:"expires_at"`
	}
	if code := a.do("POST", "/quick", nil, &resp); code != http.StatusCreated {
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
	if code := a.do("POST", "/quick", nil, &resp2); code != http.StatusCreated {
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
		if code := a.do("POST", "/quick", nil, nil); code != http.StatusCreated {
			t.Fatalf("quick #%d: status %d, want 201", i+1, code)
		}
	}
	if code := a.do("POST", "/quick", nil, nil); code != http.StatusTooManyRequests {
		t.Fatalf("quick #11: status %d, want 429", code)
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
	if code := a.do("POST", "/quick", nil, &resp); code != http.StatusCreated {
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
