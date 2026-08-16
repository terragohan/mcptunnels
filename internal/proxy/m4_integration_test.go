package proxy_test

import (
	"io"
	"net"
	"net/http"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/generalpiston/openai-tunnel-oauth/internal/oauth"
	"github.com/generalpiston/openai-tunnel-oauth/internal/store"
)

// setupM4 brings up an AS-only tunneld (root-mounted, default tenant) with a
// redirect-host allowlist and a small token rate limit.
func setupM4(t *testing.T) (issuer string, st *store.Store) {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	issuer = "http://" + ln.Addr().String()

	st, err = store.Open(filepath.Join(t.TempDir(), "tunneld.db"))
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { st.Close() })

	oauthSrv, err := oauth.NewServer(oauth.Config{
		Issuer:               issuer,
		Store:                st,
		DevUsername:          "dev",
		DevPassword:          "test-password",
		AllowedRedirectHosts: []string{"chatgpt.com"},
		TokenRatePerMin:      2,
	})
	if err != nil {
		t.Fatalf("oauth.NewServer: %v", err)
	}

	mux := http.NewServeMux()
	mux.Handle("/", oauthSrv.Handler())
	srv := &http.Server{Handler: mux}
	go srv.Serve(ln) //nolint:errcheck // test server
	t.Cleanup(func() { srv.Close() })
	return issuer, st
}

func TestM4RedirectHostAllowlist(t *testing.T) {
	issuer, st := setupM4(t)

	// Registration with an unlisted host is rejected.
	resp, err := http.Post(issuer+"/register", "application/json",
		strings.NewReader(`{"redirect_uris":["https://evil.example.com/cb"]}`))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("register unlisted host: status %d, want 400", resp.StatusCode)
	}

	// Registration with the listed host succeeds.
	resp, err = http.Post(issuer+"/register", "application/json",
		strings.NewReader(`{"redirect_uris":["https://chatgpt.com/cb"],"client_name":"ok"}`))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("register listed host: status %d, want 201", resp.StatusCode)
	}

	// /authorize with a registered-but-unlisted redirect URI (inserted
	// directly, simulating a client registered before the allowlist was
	// configured) is rejected with a plain 400.
	if err := st.InsertClient(store.DefaultTenantSlug, &store.Client{
		ClientID:     "legacy-client",
		RedirectURIs: []string{"https://evil.example.com/cb"},
		GrantTypes:   []string{"authorization_code"},
		CreatedAt:    time.Now(),
	}); err != nil {
		t.Fatal(err)
	}
	q := url.Values{
		"response_type":         {"code"},
		"client_id":             {"legacy-client"},
		"redirect_uri":          {"https://evil.example.com/cb"},
		"code_challenge":        {"x"},
		"code_challenge_method": {"S256"},
	}
	resp, err = noRedirectClient.Get(issuer + "/authorize?" + q.Encode())
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("authorize unlisted host: status %d, want 400", resp.StatusCode)
	}

	// Security headers are set on AS responses.
	resp, err = noRedirectClient.Get(issuer + "/.well-known/oauth-authorization-server")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if got := resp.Header.Get("X-Content-Type-Options"); got != "nosniff" {
		t.Errorf("X-Content-Type-Options = %q, want nosniff", got)
	}
	if got := resp.Header.Get("Referrer-Policy"); got != "no-referrer" {
		t.Errorf("Referrer-Policy = %q, want no-referrer", got)
	}
	if got := resp.Header.Get("Content-Security-Policy"); got != "frame-ancestors 'none'" {
		t.Errorf("Content-Security-Policy = %q, want frame-ancestors 'none'", got)
	}
}

func TestM4TokenRateLimit(t *testing.T) {
	issuer, _ := setupM4(t)

	// TokenRatePerMin = 2: the third request from the same IP is rejected.
	for i := 1; i <= 3; i++ {
		resp, err := noRedirectClient.PostForm(issuer+"/token", url.Values{
			"grant_type": {"refresh_token"},
			"client_id":  {"x"},
		})
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if i <= 2 && resp.StatusCode == http.StatusTooManyRequests {
			t.Fatalf("request %d rate-limited, want allowed", i)
		}
		if i == 3 && resp.StatusCode != http.StatusTooManyRequests {
			t.Fatalf("request 3: status %d, want 429", resp.StatusCode)
		}
	}
}

// TestM4AuditLog drives the main flows and asserts tenant-scoped audit rows
// were written.
func TestM4AuditLog(t *testing.T) {
	e := setupMT(t, nil)
	c := e.oauth("acme")

	// Register → dev authorize (password) → consent approve → token exchange
	// → refresh → refresh reuse. Plus one denied consent.
	clientID := c.register(chatgptRedirect)
	code := c.authorize(clientID, chatgptRedirect, "")
	_, refreshToken := c.exchange(clientID, chatgptRedirect, code)

	// One denied consent: re-run authorize up to the consent page, then deny.
	denyClient := e.oauth("acme")
	q := url.Values{
		"response_type":         {"code"},
		"client_id":             {clientID},
		"redirect_uri":          {chatgptRedirect},
		"state":                 {"s2"},
		"code_challenge":        {pkceChallenge()},
		"code_challenge_method": {"S256"},
	}
	form := url.Values{}
	for k, v := range q {
		form[k] = v
	}
	form.Set("password", "test-password")
	resp, err := noRedirectClient.PostForm(denyClient.url("/authorize"), form)
	if err != nil {
		t.Fatal(err)
	}
	page, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("authorize: status %d", resp.StatusCode)
	}
	resp, err = noRedirectClient.PostForm(denyClient.url("/authorize/consent"), url.Values{
		"consent_id": {extractConsentID(t, page)},
		"action":     {"deny"},
	})
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if loc := resp.Header.Get("Location"); !strings.Contains(loc, "error=access_denied") {
		t.Fatalf("deny: Location %q, want error=access_denied", loc)
	}

	// Refresh, then reuse the rotated-out token.
	status, tokResp := c.token(url.Values{
		"grant_type":    {"refresh_token"},
		"client_id":     {clientID},
		"refresh_token": {refreshToken},
	})
	if status != http.StatusOK {
		t.Fatalf("refresh failed: %v", tokResp)
	}
	status, tokResp = c.token(url.Values{
		"grant_type":    {"refresh_token"},
		"client_id":     {clientID},
		"refresh_token": {refreshToken},
	})
	if status != http.StatusBadRequest || tokResp["error"] != "invalid_grant" {
		t.Fatalf("reuse: status %d %v", status, tokResp)
	}

	// Assert the acme audit log.
	entries, err := e.store.ListAudit("acme", 100)
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]int{}
	for _, en := range entries {
		seen[en.Event]++
	}
	for _, want := range []string{
		"client_registered",
		"authorize_approved",
		"authorize_denied",
		"token_issued",
		"token_refreshed",
		"refresh_reuse_detected",
		"agent_connected",
	} {
		if seen[want] == 0 {
			t.Errorf("acme audit log missing event %q (have %v)", want, seen)
		}
	}

	// globex saw none of it (except its own agent connects).
	entries, err = e.store.ListAudit("globex", 100)
	if err != nil {
		t.Fatal(err)
	}
	for _, en := range entries {
		if en.Event == "client_registered" || en.Event == "token_issued" {
			t.Errorf("globex audit log leaked acme event %q", en.Event)
		}
	}
}

// TestM4IdpLoginDeniedAudit asserts the IdP allowlist denial is audited.
func TestM4IdpLoginDeniedAudit(t *testing.T) {
	// Fake provider issues user@evil.com; allowlist only permits example.com.
	e := setupM3(t, "user@evil.com", []string{"example.com"})
	c := e.oauth("acme")

	clientID := c.register("https://chatgpt.com/cb")

	q := url.Values{
		"response_type":         {"code"},
		"client_id":             {clientID},
		"redirect_uri":          {"https://chatgpt.com/cb"},
		"code_challenge":        {"x"},
		"code_challenge_method": {"S256"},
	}
	resp, err := noRedirectClient.Get(c.url("/authorize") + "?" + q.Encode())
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	resp = followRedirect(t, resp) // → fake provider /authorize
	resp.Body.Close()
	resp = followRedirect(t, resp) // → tunneld /t/acme/idp/fake/callback
	resp.Body.Close()
	resp = followRedirect(t, resp) // → 403 denial page
	page, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("callback: status %d, want 403; page %.200s", resp.StatusCode, page)
	}

	entries, err := e.store.ListAudit("acme", 10)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, en := range entries {
		if en.Event == "idp_login_denied" {
			found = true
		}
	}
	if !found {
		t.Error("audit log missing idp_login_denied")
	}
}
