package controlplane_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/generalpiston/openai-tunnel-oauth/internal/controlplane"
	"github.com/generalpiston/openai-tunnel-oauth/internal/store"
	"github.com/generalpiston/openai-tunnel-oauth/internal/store/storetest"
)

// api is a small test client for the control-plane handler.
type api struct {
	t     *testing.T
	base  string
	token string
}

func newAPI(t *testing.T, st *store.Store) *api {
	t.Helper()
	srv := httptest.NewServer(controlplane.New(st, nil).Handler())
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
	if a.token != "" {
		req.Header.Set("Authorization", "Bearer "+a.token)
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

func mustOK(a *api, method, path string, body, out any) {
	a.t.Helper()
	if code := a.do(method, path, body, out); code < 200 || code >= 300 {
		a.t.Fatalf("%s %s: status %d", method, path, code)
	}
}

// TestM1Flow exercises the full M1 control-plane flow end to end:
// bootstrap → operator token → create tenant → tenant scoping →
// service + agent key → audit.
func TestM1Flow(t *testing.T) {
	st := storetest.Open(t)
	setupToken, err := st.CreateSetupToken()
	if err != nil {
		t.Fatal(err)
	}
	a := newAPI(t, st)

	// No auth → 401.
	if code := a.do("GET", "/tenants", nil, nil); code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated /tenants: status %d, want 401", code)
	}
	// Bad setup token → 403.
	if code := a.do("POST", "/bootstrap", map[string]string{"setup_token": "tun_setup_wrong"}, nil); code != http.StatusForbidden {
		t.Fatalf("bootstrap with bad token: status %d, want 403", code)
	}

	// Bootstrap issues an operator token; the setup token is consumed.
	var boot struct {
		Token string `json:"token"`
	}
	if code := a.do("POST", "/bootstrap", map[string]string{"setup_token": setupToken}, &boot); code != http.StatusCreated {
		t.Fatalf("bootstrap: status %d, want 201", code)
	}
	if boot.Token == "" {
		t.Fatal("bootstrap returned empty token")
	}
	a.token = boot.Token

	// Create two tenants directly in the store (HTTP creation is invite-gated
	// signup, covered by TestSignupFlow); each gets an admin token.
	tenantToken := map[string]string{}
	for _, slug := range []string{"acme", "globex"} {
		if err := st.CreateTenant(slug, slug); err != nil {
			t.Fatal(err)
		}
		tok, err := st.CreateTenantToken(slug)
		if err != nil {
			t.Fatal(err)
		}
		tenantToken[slug] = tok
	}
	var tenants struct {
		Tenants []struct {
			Slug string `json:"slug"`
		} `json:"tenants"`
	}
	mustOK(a, "GET", "/tenants", nil, &tenants)
	if len(tenants.Tenants) != 3 { // default + acme + globex
		t.Fatalf("tenant list = %+v, want 3 tenants", tenants.Tenants)
	}

	// A tenant token is scoped: operator-only routes are forbidden, and
	// other tenants are forbidden.
	op := a.token
	a.token = tenantToken["acme"]
	if code := a.do("POST", "/invites", nil, nil); code != http.StatusForbidden {
		t.Fatalf("tenant token minting invites: status %d, want 403", code)
	}
	if code := a.do("GET", "/tenants", nil, nil); code != http.StatusForbidden {
		t.Fatalf("tenant token listing tenants: status %d, want 403", code)
	}
	if code := a.do("GET", "/tenants/globex/services", nil, nil); code != http.StatusForbidden {
		t.Fatalf("tenant token on other tenant: status %d, want 403", code)
	}

	// Create a service as the tenant admin; the returned agent key validates.
	var svcResp struct {
		AgentKey string `json:"agent_key"`
	}
	mustOK(a, "POST", "/tenants/acme/services", map[string]string{"name": "demo", "auth_mode": "strict"}, &svcResp)
	if svcResp.AgentKey == "" {
		t.Fatal("no agent_key in create response")
	}
	if _, err := st.ValidateAgentKey("acme", "demo", svcResp.AgentKey); err != nil {
		t.Fatalf("ValidateAgentKey: %v", err)
	}
	if _, err := st.ValidateAgentKey("globex", "demo", svcResp.AgentKey); err == nil {
		t.Fatal("agent key validated for the wrong tenant")
	}

	// agent-key issue rotates the key.
	var keyResp struct {
		AgentKey string `json:"agent_key"`
	}
	mustOK(a, "POST", "/tenants/acme/services/demo/agent-key", nil, &keyResp)
	if _, err := st.ValidateAgentKey("acme", "demo", svcResp.AgentKey); err == nil {
		t.Fatal("old agent key still valid after rotation")
	}
	if _, err := st.ValidateAgentKey("acme", "demo", keyResp.AgentKey); err != nil {
		t.Fatalf("rotated agent key: %v", err)
	}

	// Token rotate issues a new tenant token and revokes the current one.
	var rot struct {
		Token string `json:"token"`
	}
	mustOK(a, "POST", "/tenants/acme/token/rotate", nil, &rot)
	if code := a.do("GET", "/tenants/acme/services", nil, nil); code != http.StatusUnauthorized {
		t.Fatalf("old tenant token after rotate: status %d, want 401", code)
	}
	a.token = rot.Token
	var svcs struct {
		Services []struct {
			Name string `json:"name"`
		} `json:"services"`
	}
	mustOK(a, "GET", "/tenants/acme/services", nil, &svcs)
	if len(svcs.Services) != 1 || svcs.Services[0].Name != "demo" {
		t.Fatalf("service list = %+v", svcs.Services)
	}

	// Audit log captured the operations.
	a.token = op
	var audit struct {
		Entries []struct {
			Event   string `json:"event"`
			Service string `json:"service"`
		} `json:"entries"`
	}
	mustOK(a, "GET", "/tenants/acme/audit?n=50", nil, &audit)
	want := map[string]bool{"service.created": false, "agent_key.issued": false, "token.rotated": false}
	for _, e := range audit.Entries {
		if _, ok := want[e.Event]; ok {
			want[e.Event] = true
		}
	}
	for ev, seen := range want {
		if !seen {
			t.Fatalf("audit log missing event %q (entries: %+v)", ev, audit.Entries)
		}
	}

	// The globex admin sees no acme audit entries.
	a.token = tenantToken["globex"]
	audit.Entries = nil
	mustOK(a, "GET", "/tenants/globex/audit", nil, &audit)
	for _, e := range audit.Entries {
		if e.Service == "demo" {
			t.Fatalf("globex audit leaked acme entry: %+v", e)
		}
	}

	// Operator deletes the tenant; the tenant token dies with it.
	a.token = op
	if code := a.do("DELETE", "/tenants/acme", nil, nil); code != http.StatusNoContent {
		t.Fatalf("delete tenant: status %d, want 204", code)
	}
	a.token = rot.Token
	if code := a.do("GET", "/tenants/acme/services", nil, nil); code != http.StatusUnauthorized {
		t.Fatalf("token of deleted tenant: status %d, want 401", code)
	}
}

// TestBootstrapIdempotent verifies bootstrap is rejected once operator tokens
// exist, even with a fresh setup token.
func TestBootstrapIdempotent(t *testing.T) {
	st := storetest.Open(t)
	setup, _ := st.CreateSetupToken()
	a := newAPI(t, st)
	var boot struct {
		Token string `json:"token"`
	}
	mustOK(a, "POST", "/bootstrap", map[string]string{"setup_token": setup}, &boot)

	setup2, _ := st.CreateSetupToken()
	if code := a.do("POST", "/bootstrap", map[string]string{"setup_token": setup2}, nil); code != http.StatusConflict {
		t.Fatalf("second bootstrap: status %d, want 409", code)
	}
}

func TestKeysRotate(t *testing.T) {
	st := storetest.Open(t)
	if err := st.CreateTenant("acme", ""); err != nil {
		t.Fatal(err)
	}
	op, _ := st.CreateOperatorToken()
	a := newAPI(t, st)
	a.token = op
	var resp struct {
		KID string `json:"kid"`
	}
	mustOK(a, "POST", "/tenants/acme/keys/rotate", nil, &resp)
	if resp.KID == "" {
		t.Fatal("empty kid")
	}
	kid, _, err := st.SigningKey("acme")
	if err != nil {
		t.Fatal(err)
	}
	if kid != resp.KID {
		t.Fatalf("active kid %q != rotated %q", kid, resp.KID)
	}
}
