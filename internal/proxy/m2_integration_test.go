package proxy_test

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jwt"

	"github.com/generalpiston/openai-tunnel-oauth/internal/agent"
	"github.com/generalpiston/openai-tunnel-oauth/internal/config"
	"github.com/generalpiston/openai-tunnel-oauth/internal/gateway"
	"github.com/generalpiston/openai-tunnel-oauth/internal/oauth"
	"github.com/generalpiston/openai-tunnel-oauth/internal/proxy"
	"github.com/generalpiston/openai-tunnel-oauth/internal/store"
	"github.com/generalpiston/openai-tunnel-oauth/internal/tunnelproto"
)

// noRedirectClient captures 302s instead of following them.
var noRedirectClient = &http.Client{
	CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
}

// mtEnv is a full multi-tenant in-process tunneld: store, gateway, per-tenant
// AS resolver, proxy, and live agent tunnels.
type mtEnv struct {
	t         *testing.T
	base      string // public base URL, e.g. http://127.0.0.1:PORT
	srv       *http.Server
	store     *store.Store
	gw        *gateway.Gateway
	agentKeys map[string]string // "tenant/service" -> plaintext agent key
}

func (e *mtEnv) tenantIssuer(tenant string) string { return e.base + "/t/" + tenant }

// setupMT brings up an in-process multi-tenant tunneld with two tenants
// ("acme", "globex"). Services: acme/demo (strict, identity secret
// "svc-secret"), globex/demo (strict, "globex-secret"), acme/open
// (discovery_open). Each service gets a live agent tunnel to the echo
// upstream. extraIDPs optionally installs per-tenant IdP configs.
func setupMT(t *testing.T, extraIDPs map[string][]store.IDPConfig) *mtEnv {
	t.Helper()

	// Bind first so the base URL is known before the resolver is built.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	base := "http://" + ln.Addr().String()

	st, err := store.Open(filepath.Join(t.TempDir(), "tunneld.db"))
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { st.Close() })

	e := &mtEnv{t: t, base: base, store: st, agentKeys: map[string]string{}}

	for _, tenant := range []string{"acme", "globex"} {
		if err := st.CreateTenant(tenant, ""); err != nil {
			t.Fatal(err)
		}
	}
	for _, svc := range []struct {
		tenant, name, secret, mode string
	}{
		{"acme", "demo", "svc-secret", "strict"},
		{"globex", "demo", "globex-secret", "strict"},
		{"acme", "open", "", "discovery_open"},
	} {
		key, err := st.CreateService(svc.tenant, &store.Service{
			Name:           svc.name,
			IdentitySecret: svc.secret,
			AuthMode:       svc.mode,
		})
		if err != nil {
			t.Fatal(err)
		}
		e.agentKeys[svc.tenant+"/"+svc.name] = key
	}
	for tenant, cfgs := range extraIDPs {
		for i := range cfgs {
			c := cfgs[i]
			if err := st.SetIDP(tenant, &c); err != nil {
				t.Fatal(err)
			}
		}
	}

	gw := gateway.New(st)
	gw.SetAuditFunc(func(tenant, event, service, remoteAddr string) {
		_ = st.LogAudit(tenant, store.AuditEntry{Event: event, Service: service, IP: remoteAddr})
	})
	e.gw = gw

	resolver := oauth.NewResolver(oauth.ResolverConfig{
		BaseURL:         base,
		Store:           st,
		DevUsername:     "dev",
		DevPassword:     "test-password",
		AccessTokenTTL:  15 * time.Minute,
		RefreshTokenTTL: time.Hour,
		Scopes:          []string{"read", "write"},
	})

	mux := http.NewServeMux()
	mux.Handle(tunnelproto.ConnectPath, gw)
	mux.HandleFunc("GET /healthz", proxy.Healthz)
	mux.Handle("/t/{tenant}/s/", proxy.New(gw, &proxy.Auth{
		BaseURL: base,
		ValidatorFor: func(tenant string) (proxy.Validator, bool) {
			return resolver.Validator(tenant)
		},
		Store: st,
	}))
	mux.Handle("/", resolver.Handler())

	srv := &http.Server{Handler: mux}
	go srv.Serve(ln) //nolint:errcheck // test server
	t.Cleanup(func() { srv.Close() })
	e.srv = srv

	// Upstream echoes the request and any identity headers it received.
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		fmt.Fprintf(w, "method=%s path=%s body=%s subject=%s email=%s scopes=%s clientid=%s sig=%s",
			r.Method, r.URL.Path, body,
			r.Header.Get(proxy.HeaderAuthSubject),
			r.Header.Get(proxy.HeaderAuthEmail),
			r.Header.Get(proxy.HeaderAuthScopes),
			r.Header.Get(proxy.HeaderAuthClientID),
			r.Header.Get(proxy.HeaderAuthSignature))
	}))
	t.Cleanup(upstream.Close)

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	for _, ts := range []string{"acme/demo", "globex/demo", "acme/open"} {
		tenant, service, _ := strings.Cut(ts, "/")
		agentCfg := &config.AgentConfig{
			Server:   "ws://" + ln.Addr().String(),
			Tenant:   tenant,
			AgentKey: e.agentKeys[ts],
			Service:  service,
			Upstream: upstream.URL,
		}
		agentCfg.Reconnect.InitialBackoff = config.Duration(10 * time.Millisecond)
		agentCfg.Reconnect.MaxBackoff = config.Duration(200 * time.Millisecond)
		agentClient, err := agent.New(agentCfg)
		if err != nil {
			t.Fatalf("agent.New: %v", err)
		}
		go agentClient.Run(ctx) //nolint:errcheck // test teardown cancels ctx
	}

	deadline := time.Now().Add(5 * time.Second)
	for !gw.Online("acme", "demo") || !gw.Online("globex", "demo") || !gw.Online("acme", "open") {
		if time.Now().After(deadline) {
			t.Fatal("agents did not connect within 5s")
		}
		time.Sleep(10 * time.Millisecond)
	}
	return e
}

func (e *mtEnv) getJSON(path string, out any) {
	e.t.Helper()
	resp, err := http.Get(e.base + path)
	if err != nil {
		e.t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		e.t.Fatalf("GET %s: status %d: %s", path, resp.StatusCode, body)
	}
	if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
		e.t.Fatalf("GET %s: decode: %v", path, err)
	}
}

// oauthClient drives the browser-side OAuth flow against one tenant.
type oauthClient struct {
	t      *testing.T
	env    *mtEnv
	tenant string
}

func (e *mtEnv) oauth(tenant string) *oauthClient {
	return &oauthClient{t: e.t, env: e, tenant: tenant}
}

func (c *oauthClient) url(path string) string { return c.env.tenantIssuer(c.tenant) + path }

// register runs DCR and returns the client_id.
func (c *oauthClient) register(redirectURI string) string {
	c.t.Helper()
	resp, err := http.Post(c.url("/register"), "application/json", strings.NewReader(fmt.Sprintf(
		`{"redirect_uris":[%q],"client_name":"ChatGPT","grant_types":["authorization_code","refresh_token"]}`, redirectURI)))
	if err != nil {
		c.t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(resp.Body)
		c.t.Fatalf("register: status %d: %s", resp.StatusCode, body)
	}
	var reg struct {
		ClientID string `json:"client_id"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&reg); err != nil || reg.ClientID == "" {
		c.t.Fatalf("register: bad response: %v", err)
	}
	return reg.ClientID
}

var testVerifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"

func pkceChallenge() string {
	sum := sha256.Sum256([]byte(testVerifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// authorize runs the dev-password login + consent approve and returns the
// authorization code.
func (c *oauthClient) authorize(clientID, redirectURI, resource string) string {
	c.t.Helper()
	return c.authorizeWithPassword(clientID, redirectURI, resource, "test-password")
}

// authorizeWithPassword is authorize with an explicit login password.
func (c *oauthClient) authorizeWithPassword(clientID, redirectURI, resource, password string) string {
	c.t.Helper()
	q := url.Values{
		"response_type":         {"code"},
		"client_id":             {clientID},
		"redirect_uri":          {redirectURI},
		"state":                 {"state-123"},
		"scope":                 {"read write"},
		"code_challenge":        {pkceChallenge()},
		"code_challenge_method": {"S256"},
	}
	if resource != "" {
		q.Set("resource", resource)
	}

	// GET renders the dev login page.
	resp, err := noRedirectClient.Get(c.url("/authorize") + "?" + q.Encode())
	if err != nil {
		c.t.Fatal(err)
	}
	page, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK || !strings.Contains(string(page), "Authorize") {
		c.t.Fatalf("GET /authorize: status %d, page %.100s", resp.StatusCode, page)
	}

	// POST with the dev password renders the consent page.
	form := url.Values{}
	for k, v := range q {
		form[k] = v
	}
	form.Set("password", password)
	resp, err = noRedirectClient.PostForm(c.url("/authorize"), form)
	if err != nil {
		c.t.Fatal(err)
	}
	page, _ = io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK || !strings.Contains(string(page), "Approve") {
		c.t.Fatalf("POST /authorize: status %d, want consent page; page %.200s", resp.StatusCode, page)
	}
	consentID := extractConsentID(c.t, page)

	// Approve → 302 to redirect_uri with code+state.
	resp, err = noRedirectClient.PostForm(c.url("/authorize/consent"), url.Values{
		"consent_id": {consentID},
		"action":     {"approve"},
	})
	if err != nil {
		c.t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		c.t.Fatalf("consent: status %d, want 302", resp.StatusCode)
	}
	loc, err := url.Parse(resp.Header.Get("Location"))
	if err != nil {
		c.t.Fatal(err)
	}
	if loc.Scheme+"://"+loc.Host+loc.Path != redirectURI {
		c.t.Fatalf("redirect target %q, want %q", loc, redirectURI)
	}
	code := loc.Query().Get("code")
	if code == "" || loc.Query().Get("state") != "state-123" {
		c.t.Fatalf("bad redirect %q", loc)
	}
	return code
}

// token posts to the tenant's token endpoint.
func (c *oauthClient) token(v url.Values) (int, map[string]any) {
	c.t.Helper()
	resp, err := noRedirectClient.PostForm(c.url("/token"), v)
	if err != nil {
		c.t.Fatal(err)
	}
	defer resp.Body.Close()
	var out map[string]any
	body, _ := io.ReadAll(resp.Body)
	if err := json.Unmarshal(body, &out); err != nil {
		c.t.Fatalf("token response not JSON: %s", body)
	}
	return resp.StatusCode, out
}

// exchange trades a code for tokens and returns the access/refresh tokens.
func (c *oauthClient) exchange(clientID, redirectURI, code string) (access, refresh string) {
	c.t.Helper()
	status, out := c.token(url.Values{
		"grant_type":    {"authorization_code"},
		"client_id":     {clientID},
		"redirect_uri":  {redirectURI},
		"code":          {code},
		"code_verifier": {testVerifier},
	})
	if status != http.StatusOK {
		c.t.Fatalf("code exchange: status %d resp %v", status, out)
	}
	access, _ = out["access_token"].(string)
	refresh, _ = out["refresh_token"].(string)
	if access == "" || refresh == "" {
		c.t.Fatalf("missing tokens in %v", out)
	}
	return access, refresh
}

func (e *mtEnv) jwks(tenant string) jwk.Set {
	e.t.Helper()
	resp, err := http.Get(e.tenantIssuer(tenant) + "/jwks.json")
	if err != nil {
		e.t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	ks, err := jwk.Parse(body)
	if err != nil {
		e.t.Fatalf("parse jwks: %v", err)
	}
	return ks
}

// extractConsentID pulls the consent_id hidden-field value out of a consent
// page.
var consentIDRe = regexp.MustCompile(`name="consent_id" value="([^"]+)"`)

func extractConsentID(t *testing.T, page []byte) string {
	t.Helper()
	m := consentIDRe.FindSubmatch(page)
	if m == nil {
		t.Fatalf("no consent_id in page: %.300s", page)
	}
	return string(m[1])
}

const chatgptRedirect = "https://chatgpt.com/connector_platform_oauth_redirect"

// websocketDial dials the gateway connect endpoint with the given headers.
func websocketDial(ctx context.Context, url string, header http.Header) (*websocket.Conn, *http.Response, error) {
	u := "ws" + strings.TrimPrefix(url, "http")
	return websocket.Dial(ctx, u, &websocket.DialOptions{HTTPHeader: header})
}

func TestM2Metadata(t *testing.T) {
	e := setupMT(t, nil)

	// RFC 8414 path form: the tenant's AS metadata.
	var md map[string]any
	e.getJSON("/.well-known/oauth-authorization-server/t/acme", &md)
	issuer := e.tenantIssuer("acme")
	want := map[string]any{
		"issuer":                                issuer,
		"authorization_endpoint":                issuer + "/authorize",
		"token_endpoint":                        issuer + "/token",
		"registration_endpoint":                 issuer + "/register",
		"jwks_uri":                              issuer + "/jwks.json",
		"response_types_supported":              []any{"code"},
		"grant_types_supported":                 []any{"authorization_code", "refresh_token"},
		"code_challenge_methods_supported":      []any{"S256"},
		"token_endpoint_auth_methods_supported": []any{"none"},
		"scopes_supported":                      []any{"read", "write"},
	}
	for k, v := range want {
		if got := fmt.Sprint(md[k]); got != fmt.Sprint(v) {
			t.Errorf("metadata[%s] = %v, want %v", k, md[k], v)
		}
	}

	// Root form is served too (permissive fallback for the default tenant).
	e.getJSON("/.well-known/oauth-authorization-server", &md)
	if md["issuer"] != e.base+"/t/default" {
		t.Errorf("root AS metadata issuer = %v, want %s/t/default", md["issuer"], e.base)
	}

	// RFC 9728 protected-resource metadata for one service.
	var pr map[string]any
	e.getJSON("/.well-known/oauth-protected-resource/t/acme/s/demo", &pr)
	if pr["resource"] != e.base+"/t/acme/s/demo" {
		t.Errorf("resource = %v, want %s/t/acme/s/demo", pr["resource"], e.base)
	}
	if fmt.Sprint(pr["authorization_servers"]) != fmt.Sprint([]any{issuer}) {
		t.Errorf("authorization_servers = %v, want [%s]", pr["authorization_servers"], issuer)
	}

	// Unknown tenant → 404.
	resp, err := http.Get(e.base + "/.well-known/oauth-authorization-server/t/nope")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("unknown tenant metadata: status %d, want 404", resp.StatusCode)
	}
}

// TestM2FullFlow drives the complete ChatGPT-style OAuth flow end to end
// against a per-tenant AS.
func TestM2FullFlow(t *testing.T) {
	e := setupMT(t, nil)
	c := e.oauth("acme")
	resource := e.tenantIssuer("acme") + "/s/demo"

	clientID := c.register(chatgptRedirect)

	// http:// redirect URIs must be rejected.
	badReg, err := http.Post(c.url("/register"), "application/json",
		strings.NewReader(`{"redirect_uris":["http://evil.example/cb"]}`))
	if err != nil {
		t.Fatal(err)
	}
	badReg.Body.Close()
	if badReg.StatusCode != http.StatusBadRequest {
		t.Fatalf("register with http redirect: status %d, want 400", badReg.StatusCode)
	}

	code := c.authorize(clientID, chatgptRedirect, resource)

	// Wrong verifier → 400 invalid_grant.
	status, tokResp := c.token(url.Values{
		"grant_type":    {"authorization_code"},
		"client_id":     {clientID},
		"redirect_uri":  {chatgptRedirect},
		"code":          {code},
		"code_verifier": {"wrong-verifier"},
	})
	if status != http.StatusBadRequest || tokResp["error"] != "invalid_grant" {
		t.Fatalf("wrong verifier: status %d resp %v", status, tokResp)
	}

	accessToken, refreshToken := c.exchange(clientID, chatgptRedirect, code)

	// Replayed code → 400.
	status, tokResp = c.token(url.Values{
		"grant_type":    {"authorization_code"},
		"client_id":     {clientID},
		"redirect_uri":  {chatgptRedirect},
		"code":          {code},
		"code_verifier": {testVerifier},
	})
	if status != http.StatusBadRequest || tokResp["error"] != "invalid_grant" {
		t.Fatalf("replayed code: status %d resp %v", status, tokResp)
	}

	// JWT verifies against the tenant's JWKS and carries tenant-scoped claims.
	parsed, err := jwt.ParseString(accessToken, jwt.WithKeySet(e.jwks("acme")), jwt.WithValidate(true))
	if err != nil {
		t.Fatalf("access token does not verify against acme jwks: %v", err)
	}
	if parsed.Issuer() != e.tenantIssuer("acme") {
		t.Errorf("iss = %q, want %q", parsed.Issuer(), e.tenantIssuer("acme"))
	}
	if parsed.Subject() != "dev" {
		t.Errorf("sub = %q, want dev", parsed.Subject())
	}
	if aud := parsed.Audience(); len(aud) != 1 || aud[0] != resource {
		t.Errorf("aud = %v, want [%s]", aud, resource)
	}

	// Proxied request without token → 401 + WWW-Authenticate challenge.
	resp, err := noRedirectClient.Get(e.tenantIssuer("acme") + "/s/demo/echo")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("no token: status %d, want 401", resp.StatusCode)
	}
	wantAuth := fmt.Sprintf(`Bearer realm="%s", resource_metadata="%s/.well-known/oauth-protected-resource/t/acme/s/demo"`,
		e.tenantIssuer("acme"), e.base)
	if got := resp.Header.Get("WWW-Authenticate"); got != wantAuth {
		t.Fatalf("WWW-Authenticate = %q, want %q", got, wantAuth)
	}

	// Proxied request with token → 200 through the tunnel, with signed
	// identity headers.
	req, _ := http.NewRequest(http.MethodGet, e.tenantIssuer("acme")+"/s/demo/echo", nil)
	req.Header.Set("Authorization", "Bearer "+accessToken)
	resp, err = noRedirectClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK || !strings.Contains(string(body), "path=/echo") {
		t.Fatalf("with token: status %d body %q", resp.StatusCode, body)
	}
	for _, want := range []string{"subject=dev", "clientid=" + clientID, "scopes=read write"} {
		if !strings.Contains(string(body), want) {
			t.Errorf("upstream echo missing %q: %s", want, body)
		}
	}
	wantSig := proxy.SignIdentity("svc-secret", "dev", "", "read write", clientID)
	if !strings.Contains(string(body), "sig="+wantSig) {
		t.Errorf("HMAC mismatch: %s, want sig=%s", body, wantSig)
	}

	// Refresh rotation; reusing the rotated-out token revokes the chain.
	status, tokResp = c.token(url.Values{
		"grant_type":    {"refresh_token"},
		"client_id":     {clientID},
		"refresh_token": {refreshToken},
	})
	if status != http.StatusOK {
		t.Fatalf("refresh: status %d resp %v", status, tokResp)
	}
	refresh2, _ := tokResp["refresh_token"].(string)
	if refresh2 == "" || refresh2 == refreshToken {
		t.Fatalf("refresh did not rotate: %v", tokResp)
	}
	status, tokResp = c.token(url.Values{
		"grant_type":    {"refresh_token"},
		"client_id":     {clientID},
		"refresh_token": {refreshToken},
	})
	if status != http.StatusBadRequest || tokResp["error"] != "invalid_grant" {
		t.Fatalf("reused refresh token: status %d resp %v", status, tokResp)
	}
	status, tokResp = c.token(url.Values{
		"grant_type":    {"refresh_token"},
		"client_id":     {clientID},
		"refresh_token": {refresh2},
	})
	if status != http.StatusBadRequest || tokResp["error"] != "invalid_grant" {
		t.Fatalf("chain not revoked after reuse: status %d resp %v", status, tokResp)
	}
}

// TestM2TenantIsolation verifies tokens and keys are tenant-scoped.
func TestM2TenantIsolation(t *testing.T) {
	e := setupMT(t, nil)

	clientID := e.oauth("acme").register(chatgptRedirect)
	code := e.oauth("acme").authorize(clientID, chatgptRedirect, e.tenantIssuer("acme")+"/s/demo")
	acmeToken, _ := e.oauth("acme").exchange(clientID, chatgptRedirect, code)

	// A token minted for acme must not verify against globex's JWKS...
	if _, err := jwt.ParseString(acmeToken, jwt.WithKeySet(e.jwks("globex")), jwt.WithValidate(true)); err == nil {
		t.Fatal("acme token verified against globex JWKS")
	}

	// ... and must 401 on globex's service (issuer mismatch).
	req, _ := http.NewRequest(http.MethodGet, e.tenantIssuer("globex")+"/s/demo/echo", nil)
	req.Header.Set("Authorization", "Bearer "+acmeToken)
	resp, err := noRedirectClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("acme token on globex service: status %d, want 401", resp.StatusCode)
	}

	// Unknown tenant → 404, unknown service → 404.
	for _, path := range []string{"/t/nope/s/demo/echo", "/t/acme/s/nope/echo"} {
		resp, err := noRedirectClient.Get(e.base + path)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusNotFound {
			t.Fatalf("GET %s: status %d, want 404", path, resp.StatusCode)
		}
	}

	// A client registered under acme is unknown to globex.
	resp, err = noRedirectClient.Get(e.tenantIssuer("globex") + "/authorize?" + url.Values{
		"response_type":         {"code"},
		"client_id":             {clientID},
		"redirect_uri":          {chatgptRedirect},
		"code_challenge":        {pkceChallenge()},
		"code_challenge_method": {"S256"},
	}.Encode())
	if err != nil {
		t.Fatal(err)
	}
	page, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest || !strings.Contains(string(page), "unknown client_id") {
		t.Fatalf("cross-tenant client: status %d, page %.100s", resp.StatusCode, page)
	}
}

// TestM2DiscoveryOpen verifies discovery_open mode is per-service.
func TestM2DiscoveryOpen(t *testing.T) {
	e := setupMT(t, nil)
	openURL := e.tenantIssuer("acme") + "/s/open/mcp"

	post := func(body string) *http.Response {
		t.Helper()
		resp, err := noRedirectClient.Post(openURL, "application/json", strings.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		return resp
	}

	resp := post(`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("tools/list: status %d, want 200", resp.StatusCode)
	}

	resp = post(`{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"x"}}`)
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("tools/call: status %d, want 401", resp.StatusCode)
	}

	resp = post(`[{"jsonrpc":"2.0","id":1,"method":"initialize"},{"jsonrpc":"2.0","id":2,"method":"ping"}]`)
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("batch: status %d, want 401", resp.StatusCode)
	}

	resp, err := noRedirectClient.Get(openURL)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /s/open/mcp: status %d, want 200", resp.StatusCode)
	}

	resp, err = noRedirectClient.Get(e.tenantIssuer("acme") + "/s/open/echo")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("GET /s/open/echo: status %d, want 401", resp.StatusCode)
	}

	// The strict service rejects tokenless MCP calls.
	resp, err = noRedirectClient.Post(e.tenantIssuer("acme")+"/s/demo/mcp", "application/json",
		strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("strict service tools/list: status %d, want 401", resp.StatusCode)
	}
}

// TestM2AgentAuth verifies the gateway authenticates agents with store-issued
// keys scoped to (tenant, service).
func TestM2AgentAuth(t *testing.T) {
	e := setupMT(t, nil)

	dial := func(tenant, service, key string) int {
		t.Helper()
		header := http.Header{}
		header.Set("Authorization", tunnelproto.AuthorizationHeader(key))
		header.Set(tunnelproto.HeaderTenant, tenant)
		header.Set(tunnelproto.HeaderServiceName, service)
		_, resp, err := websocketDial(context.Background(), e.base+tunnelproto.ConnectPath, header)
		if err != nil && resp == nil {
			t.Fatalf("dial: %v", err)
		}
		return resp.StatusCode
	}

	if code := dial("acme", "demo", "tun_agent_wrong"); code != http.StatusUnauthorized {
		t.Fatalf("wrong key: status %d, want 401", code)
	}
	// A valid key for acme/demo must not authenticate globex/demo...
	if code := dial("globex", "demo", e.agentKeys["acme/demo"]); code != http.StatusUnauthorized {
		t.Fatalf("cross-tenant key: status %d, want 401", code)
	}
	// ... nor a different service under the same tenant.
	if code := dial("acme", "open", e.agentKeys["acme/demo"]); code != http.StatusUnauthorized {
		t.Fatalf("cross-service key: status %d, want 401", code)
	}
	if code := dial("nope", "demo", e.agentKeys["acme/demo"]); code != http.StatusUnauthorized {
		t.Fatalf("unknown tenant: status %d, want 401", code)
	}
}
