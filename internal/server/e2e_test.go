package server_test

import (
	"bytes"
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
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/terragohan/mcptunnels/internal/agent"
	"github.com/terragohan/mcptunnels/internal/config"
	"github.com/terragohan/mcptunnels/internal/gateway"
	"github.com/terragohan/mcptunnels/internal/server"
	"github.com/terragohan/mcptunnels/internal/store/storetest"
)

// quickResp mirrors the POST /api/v1/quick response.
type quickResp struct {
	Tenant    string `json:"tenant"`
	Service   string `json:"service"`
	AgentKey  string `json:"agent_key"`
	ExpiresAt int64  `json:"expires_at"`
}

// startTunneld serves the full tunneld handler (the composition root from
// server.NewHandler) on a real loopback listener. The listener is bound
// first so the OAuth metadata advertised inside responses uses a genuinely
// reachable base URL.
func startTunneld(t *testing.T) (string, *gateway.Gateway) {
	t.Helper()
	st := storetest.Open(t)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	base := "http://" + ln.Addr().String()
	handler, gw := server.NewHandler(st, base)
	go http.Serve(ln, handler) //nolint:errcheck // test teardown closes ln
	t.Cleanup(func() { ln.Close() })
	return base, gw
}

func createQuick(t *testing.T, base string, body map[string]any) quickResp {
	t.Helper()
	data, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := http.Post(base+"/api/v1/quick", "application/json", bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("quick: status %d, want 201", resp.StatusCode)
	}
	var qr quickResp
	if err := json.NewDecoder(resp.Body).Decode(&qr); err != nil {
		t.Fatal(err)
	}
	return qr
}

func waitFor(t *testing.T, cond func() bool, msg string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatal(msg)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// noRedirectClient returns an HTTP client that does not follow 302s, so the
// OAuth redirects can be inspected directly.
func noRedirectClient() *http.Client {
	return &http.Client{CheckRedirect: func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}}
}

// runOAuthFlow walks the full OAuth 2.1 flow against the in-process tunneld
// over real HTTP, mirroring what an MCP client (e.g. ChatGPT) does:
// RFC 7591 DCR, the password-gated authorize form, then the PKCE S256 token
// exchange. It asserts the intermediate steps (form on GET, "Wrong password"
// on a bad POST, no redirect) and returns the access token.
func runOAuthFlow(t *testing.T, base, tenant, password, redirectURI string) string {
	t.Helper()
	as := base + "/t/" + tenant
	client := noRedirectClient()

	// DCR: register a public client.
	regResp, err := http.Post(as+"/register", "application/json",
		strings.NewReader(fmt.Sprintf(`{"redirect_uris":[%q],"token_endpoint_auth_method":"none","client_name":"e2e"}`, redirectURI)))
	if err != nil {
		t.Fatal(err)
	}
	defer regResp.Body.Close()
	if regResp.StatusCode != http.StatusCreated {
		t.Fatalf("register: status %d, want 201", regResp.StatusCode)
	}
	var reg struct {
		ClientID string `json:"client_id"`
	}
	if err := json.NewDecoder(regResp.Body).Decode(&reg); err != nil || reg.ClientID == "" {
		t.Fatalf("register: bad response: %v", err)
	}

	verifier := "e2e-verifier-43-chars-long-for-pkce-s256!!"
	h := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(h[:])
	authParams := fmt.Sprintf("response_type=code&client_id=%s&redirect_uri=%s&code_challenge=%s&code_challenge_method=S256&state=e2e",
		reg.ClientID, url.QueryEscape(redirectURI), challenge)

	// No password yet → the password form is served.
	authResp, err := client.Get(as + "/authorize?" + authParams)
	if err != nil {
		t.Fatal(err)
	}
	authResp.Body.Close()
	if authResp.StatusCode != http.StatusOK {
		t.Fatalf("authorize GET: status %d, want 200 (password form)", authResp.StatusCode)
	}

	// Wrong password → form re-rendered with an error, no redirect.
	form := url.Values{
		"client_id":             {reg.ClientID},
		"redirect_uri":          {redirectURI},
		"response_type":         {"code"},
		"code_challenge":        {challenge},
		"code_challenge_method": {"S256"},
		"state":                 {"e2e"},
		"password":              {"wrong"},
	}
	authResp, err = client.PostForm(as+"/authorize", form)
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(authResp.Body)
	authResp.Body.Close()
	if err != nil {
		t.Fatal(err)
	}
	if authResp.StatusCode != http.StatusOK {
		t.Fatalf("authorize wrong password: status %d, want 200 (form)", authResp.StatusCode)
	}
	if authResp.Header.Get("Location") != "" {
		t.Fatal("authorize wrong password: got a redirect, want the form re-rendered")
	}
	if !strings.Contains(string(body), "Wrong password") {
		t.Fatal("authorize wrong password: response missing error message")
	}

	// Correct password → 302 with a one-time code.
	form.Set("password", password)
	authResp, err = client.PostForm(as+"/authorize", form)
	if err != nil {
		t.Fatal(err)
	}
	authResp.Body.Close()
	if authResp.StatusCode != http.StatusFound {
		t.Fatalf("authorize correct password: status %d, want 302", authResp.StatusCode)
	}
	loc, err := url.Parse(authResp.Header.Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	code := loc.Query().Get("code")
	if code == "" {
		t.Fatal("authorize: no code in redirect")
	}
	if got := loc.Query().Get("state"); got != "e2e" {
		t.Fatalf("authorize: state = %q, want e2e", got)
	}

	// Token exchange with PKCE S256.
	tokenResp, err := http.PostForm(as+"/token", url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"client_id":     {reg.ClientID},
		"redirect_uri":  {redirectURI},
		"code_verifier": {verifier},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer tokenResp.Body.Close()
	if tokenResp.StatusCode != http.StatusOK {
		t.Fatalf("token: status %d, want 200", tokenResp.StatusCode)
	}
	var tok struct {
		AccessToken string `json:"access_token"`
		TokenType   string `json:"token_type"`
	}
	if err := json.NewDecoder(tokenResp.Body).Decode(&tok); err != nil {
		t.Fatal(err)
	}
	if tok.AccessToken == "" || tok.TokenType != "Bearer" {
		t.Fatalf("token: %+v, want a Bearer access token", tok)
	}
	return tok.AccessToken
}

// TestQuickTunnelEndToEnd exercises the whole tunneld surface in-process over
// real TCP/HTTP: quick-tunnel creation, agent dial-out, the OAuth 2.1
// protected public endpoint (discovery → password-gated authorize → PKCE
// token → authenticated proxying), agent reconnect, concurrent requests, and
// the Ctrl-C delete path.
func TestQuickTunnelEndToEnd(t *testing.T) {
	base, gw := startTunneld(t)
	const password = "pw"
	var qr quickResp
	var agentCfg *config.AgentConfig
	var token string

	// Local MCP upstream; it echoes the JSON-RPC id back in its result.
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			ID any `json:"id"`
		}
		json.NewDecoder(r.Body).Decode(&req) //nolint:errcheck // upstream forgives
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"jsonrpc":"2.0","id":%v,"result":{"up":"%s"}}`, req.ID, r.URL.Path)
	}))
	defer upstream.Close()

	t.Run("quick create", func(t *testing.T) {
		qr = createQuick(t, base, map[string]any{"auth": true, "password": password})
		if !strings.HasPrefix(qr.Tenant, "q-") || qr.Service == "" || qr.AgentKey == "" {
			t.Fatalf("quick response missing fields: %+v", qr)
		}
		if d := time.Until(time.Unix(qr.ExpiresAt, 0)); d < 23*time.Hour || d > 24*time.Hour {
			t.Fatalf("expires_at is %v from now, want ~24h", d)
		}
	})

	startAgent := func(ctx context.Context) {
		agentCfg = &config.AgentConfig{
			Server:   "ws://" + mustHost(t, base),
			Tenant:   qr.Tenant,
			AgentKey: qr.AgentKey,
			Service:  qr.Service,
			Upstream: upstream.URL,
		}
		agentCfg.Reconnect.InitialBackoff = config.Duration(10 * time.Millisecond)
		agentCfg.Reconnect.MaxBackoff = config.Duration(200 * time.Millisecond)
		c, err := agent.New(agentCfg)
		if err != nil {
			t.Fatalf("agent.New: %v", err)
		}
		go c.Run(ctx) //nolint:errcheck // test teardown cancels ctx
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	// For the reconnect subtest: a second agent context that survives its
	// subtest (the concurrency subtest rides that tunnel).
	ctx2, cancel2 := context.WithCancel(context.Background())
	defer cancel2()

	t.Run("agent connects", func(t *testing.T) {
		startAgent(ctx)
		waitFor(t, func() bool { return gw.Online(qr.Tenant, qr.Service) },
			"agent did not connect within 5s")
	})

	t.Run("no token is rejected", func(t *testing.T) {
		resp, err := http.Get(fmt.Sprintf("%s/t/%s/s/%s/mcp", base, qr.Tenant, qr.Service))
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("status %d, want 401", resp.StatusCode)
		}
		www := resp.Header.Get("WWW-Authenticate")
		if !strings.Contains(www, `resource_metadata="`) {
			t.Fatalf("WWW-Authenticate = %q, want resource_metadata=", www)
		}
	})

	t.Run("discovery metadata", func(t *testing.T) {
		// 401 → RFC 9728 protected-resource metadata URL → AS metadata.
		resp, err := http.Get(fmt.Sprintf("%s/t/%s/s/%s/mcp", base, qr.Tenant, qr.Service))
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		www := resp.Header.Get("WWW-Authenticate")
		metaURL := strings.TrimSuffix(strings.TrimPrefix(www, `Bearer resource_metadata="`), `"`)

		var prm struct {
			Resource             string   `json:"resource"`
			AuthorizationServers []string `json:"authorization_servers"`
		}
		getJSON(t, metaURL, &prm)
		wantResource := fmt.Sprintf("%s/t/%s/s/%s", base, qr.Tenant, qr.Service)
		if prm.Resource != wantResource {
			t.Errorf("resource = %q, want %q", prm.Resource, wantResource)
		}
		if len(prm.AuthorizationServers) != 1 {
			t.Fatalf("authorization_servers = %v, want one", prm.AuthorizationServers)
		}
		issuer := prm.AuthorizationServers[0]
		if wantIssuer := base + "/t/" + qr.Tenant; issuer != wantIssuer {
			t.Fatalf("authorization server = %q, want %q", issuer, wantIssuer)
		}

		var asm struct {
			Issuer                string   `json:"issuer"`
			AuthorizationEndpoint string   `json:"authorization_endpoint"`
			TokenEndpoint         string   `json:"token_endpoint"`
			RegistrationEndpoint  string   `json:"registration_endpoint"`
			JWKSURI               string   `json:"jwks_uri"`
			CodeChallengeMethods  []string `json:"code_challenge_methods_supported"`
			ResponseTypes         []string `json:"response_types_supported"`
		}
		getJSON(t, issuer+"/.well-known/oauth-authorization-server", &asm)
		if asm.Issuer != issuer {
			t.Errorf("issuer = %q, want %q", asm.Issuer, issuer)
		}
		for name, ep := range map[string]string{
			"authorization_endpoint": asm.AuthorizationEndpoint,
			"token_endpoint":         asm.TokenEndpoint,
			"registration_endpoint":  asm.RegistrationEndpoint,
		} {
			if !strings.HasPrefix(ep, issuer+"/") {
				t.Errorf("%s = %q, want under %q", name, ep, issuer)
			}
		}
		if !slicesContains(asm.CodeChallengeMethods, "S256") {
			t.Errorf("code_challenge_methods_supported = %v, want S256", asm.CodeChallengeMethods)
		}
		if !slicesContains(asm.ResponseTypes, "code") {
			t.Errorf("response_types_supported = %v, want code", asm.ResponseTypes)
		}

		// The advertised metadata endpoints genuinely resolve.
		var jwks struct {
			Keys []any `json:"keys"`
		}
		getJSON(t, asm.JWKSURI, &jwks)
		if len(jwks.Keys) == 0 {
			t.Error("jwks_uri returned no keys")
		}
	})

	t.Run("oauth flow", func(t *testing.T) {
		token = runOAuthFlow(t, base, qr.Tenant, password, "https://example.com/cb")
	})

	t.Run("authenticated call", func(t *testing.T) {
		resp := postRPC(t, base, qr, token, 1, "initialize")
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("status %d, want 200", resp.StatusCode)
		}
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(body), `"id":1`) || !strings.Contains(string(body), `"up":"/mcp"`) {
			t.Fatalf("response %s, want echoed id and upstream result", body)
		}
	})

	t.Run("token from another tenant is rejected", func(t *testing.T) {
		qr2 := createQuick(t, base, map[string]any{"auth": true, "password": "pw2"})
		token2 := runOAuthFlow(t, base, qr2.Tenant, "pw2", "https://example.com/cb")
		resp := postRPC(t, base, qr, token2, 2, "tools/list")
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("cross-tenant token: status %d, want 401", resp.StatusCode)
		}
	})

	t.Run("reconnect", func(t *testing.T) {
		cancel()
		waitFor(t, func() bool { return !gw.Online(qr.Tenant, qr.Service) },
			"agent did not go offline within 5s")

		// While offline the public endpoint 502s.
		resp := postRPC(t, base, qr, token, 3, "tools/list")
		resp.Body.Close()
		if resp.StatusCode != http.StatusBadGateway {
			t.Fatalf("offline: status %d, want 502", resp.StatusCode)
		}

		// A fresh agent with the same config comes back online. It rides
		// the ctx2 created at the outer level so it outlives this subtest —
		// the concurrency subtest below uses this tunnel.
		startAgent(ctx2)
		waitFor(t, func() bool { return gw.Online(qr.Tenant, qr.Service) },
			"reconnected agent did not come online within 5s")

		resp = postRPC(t, base, qr, token, 4, "tools/list")
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("after reconnect: status %d, want 200", resp.StatusCode)
		}
	})

	t.Run("concurrent requests", func(t *testing.T) {
		var wg sync.WaitGroup
		for i := 0; i < 20; i++ {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				resp := postRPC(t, base, qr, token, i, "tools/list")
				defer resp.Body.Close()
				if resp.StatusCode != http.StatusOK {
					t.Errorf("req %d: status %d, want 200", i, resp.StatusCode)
					return
				}
				body, err := io.ReadAll(resp.Body)
				if err != nil || !strings.Contains(string(body), fmt.Sprintf(`"id":%d`, i)) {
					t.Errorf("req %d: bad correlation: %s (%v)", i, body, err)
				}
			}(i)
		}
		wg.Wait()
	})

	t.Run("ctrl-c deletes the tunnel", func(t *testing.T) {
		req, err := http.NewRequest(http.MethodDelete, base+"/api/v1/quick/"+qr.Tenant, nil)
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Authorization", "Bearer "+qr.AgentKey)
		req.Header.Set("X-Service-Name", qr.Service)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusNoContent {
			t.Fatalf("delete: status %d, want 204", resp.StatusCode)
		}

		resp = postRPC(t, base, qr, token, 5, "tools/list")
		resp.Body.Close()
		if resp.StatusCode != http.StatusNotFound {
			t.Fatalf("public URL after delete: status %d, want 404", resp.StatusCode)
		}
	})
}

func mustHost(t *testing.T, base string) string {
	t.Helper()
	u, err := url.Parse(base)
	if err != nil {
		t.Fatal(err)
	}
	return u.Host
}

func getJSON(t *testing.T, url string, out any) {
	t.Helper()
	resp, err := http.Get(url)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET %s: status %d, want 200", url, resp.StatusCode)
	}
	if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
		t.Fatalf("GET %s: %v", url, err)
	}
}

func postRPC(t *testing.T, base string, qr quickResp, token string, id int, method string) *http.Response {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost,
		fmt.Sprintf("%s/t/%s/s/%s/mcp", base, qr.Tenant, qr.Service),
		strings.NewReader(fmt.Sprintf(`{"jsonrpc":"2.0","id":%d,"method":%q}`, id, method)))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	return resp
}

func slicesContains(ss []string, want string) bool {
	for _, s := range ss {
		if s == want {
			return true
		}
	}
	return false
}
