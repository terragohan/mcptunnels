package proxy_test

import (
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/url"
	"path/filepath"
	"strings"
	"testing"

	"github.com/generalpiston/openai-tunnel-oauth/internal/controlplane"
	"github.com/generalpiston/openai-tunnel-oauth/internal/oauth"
	"github.com/generalpiston/openai-tunnel-oauth/internal/store"
)

// setupM5 brings up an AS resolver plus the control plane wired together
// (as in tunneld), with an operator token, on one listener. No agents.
func setupM5(t *testing.T) (base string, st *store.Store, opToken string) {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	base = "http://" + ln.Addr().String()

	st, err = store.Open(filepath.Join(t.TempDir(), "tunneld.db"))
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { st.Close() })

	if err := st.CreateTenant("acme", ""); err != nil {
		t.Fatal(err)
	}
	opToken, err = st.CreateOperatorToken()
	if err != nil {
		t.Fatal(err)
	}

	resolver := oauth.NewResolver(oauth.ResolverConfig{
		BaseURL:     base,
		Store:       st,
		DevUsername: "dev",
		DevPassword: "test-password",
	})
	cp := controlplane.New(st, resolver)

	mux := http.NewServeMux()
	mux.Handle("/api/v1/", cp.Handler())
	mux.Handle("/", resolver.Handler())
	srv := &http.Server{Handler: mux}
	go srv.Serve(ln) //nolint:errcheck // test server
	t.Cleanup(func() { srv.Close() })
	return base, st, opToken
}

func apiCall(t *testing.T, method, url, token string, body any) (*http.Response, map[string]any) {
	t.Helper()
	var rdr *strings.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		rdr = strings.NewReader(string(data))
	} else {
		rdr = strings.NewReader("")
	}
	req, err := http.NewRequest(method, url, rdr)
	if err != nil {
		t.Fatal(err)
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var out map[string]any
	data, _ := io.ReadAll(resp.Body)
	json.Unmarshal(data, &out) //nolint:errcheck // best-effort decode
	// Reattach for status inspection only.
	return &http.Response{StatusCode: resp.StatusCode, Header: resp.Header}, out
}

// authorizePageGET fetches /t/acme/authorize with minimal valid params
// against a registered client and returns the status and body/Location.
func authorizeGet(t *testing.T, base, clientID string) (int, string, string) {
	t.Helper()
	resp, err := noRedirectClient.Get(base + "/t/acme/authorize?" + url.Values{
		"response_type":         {"code"},
		"client_id":             {clientID},
		"redirect_uri":          {"https://chatgpt.com/cb"},
		"code_challenge":        {"x"},
		"code_challenge_method": {"S256"},
	}.Encode())
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	page, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(page), resp.Header.Get("Location")
}

// TestM5ResolverInvalidation verifies that idp set/delete and keys rotate via
// the control plane take effect immediately, without a tunneld restart.
func TestM5ResolverInvalidation(t *testing.T) {
	base, st, opToken := setupM5(t)
	api := "/api/v1"

	// Register a client directly (dev login tenant, no IdP yet).
	if err := st.InsertClient("acme", &store.Client{
		ClientID:     "c1",
		RedirectURIs: []string{"https://chatgpt.com/cb"},
		GrantTypes:   []string{"authorization_code"},
	}); err != nil {
		t.Fatal(err)
	}

	// No IdP → dev login page.
	status, page, _ := authorizeGet(t, base, "c1")
	if status != http.StatusOK || !strings.Contains(page, "password") {
		t.Fatalf("no-IdP authorize: status %d, page %.100s", status, page)
	}

	// Prime the resolver cache with the no-IdP AS, then set an IdP via the
	// control plane. The very next request must auto-redirect to it.
	fake := newFakeOIDC(t, "user@example.com")
	resp, out := apiCall(t, "PUT", base+api+"/tenants/acme/idp", opToken, map[string]any{
		"name":          "fake",
		"client_id":     "fake-client",
		"client_secret": "fake-secret",
		"issuer":        fake.srv.URL,
	})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("idp set: status %d, %v", resp.StatusCode, out)
	}
	status, _, loc := authorizeGet(t, base, "c1")
	if status != http.StatusFound || !strings.HasPrefix(loc, "/t/acme/idp/fake/login?") {
		t.Fatalf("after idp set: status %d, Location %q, want redirect to /t/acme/idp/fake/login", status, loc)
	}

	// Delete the IdP → dev login page again, without restart.
	resp, _ = apiCall(t, "DELETE", base+api+"/tenants/acme/idp?name=fake", opToken, nil)
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("idp delete: status %d", resp.StatusCode)
	}
	status, page, _ = authorizeGet(t, base, "c1")
	if status != http.StatusOK || !strings.Contains(page, "password") {
		t.Fatalf("after idp delete: status %d, page %.100s", status, page)
	}

	// Keys rotate → the JWKS kid changes immediately.
	kidOf := func() string {
		t.Helper()
		resp, err := http.Get(base + "/t/acme/jwks.json")
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		var doc struct {
			Keys []struct {
				KID string `json:"kid"`
			} `json:"keys"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil || len(doc.Keys) == 0 {
			t.Fatalf("jwks decode: %v", err)
		}
		return doc.Keys[0].KID
	}
	oldKID := kidOf()
	resp, _ = apiCall(t, "POST", base+api+"/tenants/acme/keys/rotate", opToken, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("keys rotate: status %d", resp.StatusCode)
	}
	if newKID := kidOf(); newKID == oldKID {
		t.Fatalf("jwks kid unchanged after rotation: %q", newKID)
	}
}

// TestM5TenantDisable verifies a disabled tenant's public endpoints 404 while
// the control plane keeps working, and enable restores them.
func TestM5TenantDisable(t *testing.T) {
	base, st, opToken := setupM5(t)
	api := "/api/v1"

	mdStatus := func() int {
		t.Helper()
		resp, err := http.Get(base + "/.well-known/oauth-authorization-server/t/acme")
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp.StatusCode
	}

	if mdStatus() != http.StatusOK {
		t.Fatal("tenant metadata should be 200 before disable")
	}

	// Tenant admins cannot disable tenants (operator only).
	if err := st.CreateTenant("globex", ""); err != nil {
		t.Fatal(err)
	}
	tenTok, err := st.CreateTenantToken("globex")
	if err != nil {
		t.Fatal(err)
	}
	resp, _ := apiCall(t, "POST", base+api+"/tenants/acme/disable", tenTok, nil)
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("tenant token disabling tenant: status %d, want 403", resp.StatusCode)
	}

	resp, _ = apiCall(t, "POST", base+api+"/tenants/acme/disable", opToken, nil)
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("disable: status %d", resp.StatusCode)
	}
	if s := mdStatus(); s != http.StatusNotFound {
		t.Fatalf("disabled tenant metadata: status %d, want 404", s)
	}

	// Enable restores access without restart.
	resp, _ = apiCall(t, "POST", base+api+"/tenants/acme/enable", opToken, nil)
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("enable: status %d", resp.StatusCode)
	}
	if s := mdStatus(); s != http.StatusOK {
		t.Fatalf("re-enabled tenant metadata: status %d, want 200", s)
	}

	// Unknown tenant → 404 from the control plane too.
	resp, _ = apiCall(t, "POST", base+api+"/tenants/nope/disable", opToken, nil)
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("disable unknown tenant: status %d, want 404", resp.StatusCode)
	}
}
