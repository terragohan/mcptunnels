package oauth_test

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/terragohan/mcptunnels/internal/oauth"
	"github.com/terragohan/mcptunnels/internal/store"
	"github.com/terragohan/mcptunnels/internal/store/storetest"
)

// TestOAuthFlow exercises the full authorization-code flow: DCR register →
// authorize (auto-approved) → token exchange. It verifies that the resulting
// access token passes validation.
func TestOAuthFlow(t *testing.T) {
	st := storetest.Open(t)
	expires := time.Now().Add(time.Hour)
	if err := st.CreateTenantExpiry("q-test", "quick tunnel", &expires); err != nil {
		t.Fatal(err)
	}

	base := "http://localhost"
	srv, err := oauth.NewServer(st, base, "q-test", expires)
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	// 1. DCR: register a public client.
	regBody := `{"redirect_uris":["https://chatgpt.com/connector_platform_oauth_redirect"],"token_endpoint_auth_method":"none","client_name":"test"}`
	resp, err := http.Post(ts.URL+"/register", "application/json", strings.NewReader(regBody))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("register: status %d, want 201", resp.StatusCode)
	}
	var regResp struct {
		ClientID string `json:"client_id"`
	}
	json.NewDecoder(resp.Body).Decode(&regResp)
	if regResp.ClientID == "" {
		t.Fatal("register: empty client_id")
	}

	// 2. Authorize: auto-approved, redirects with code.
	verifier := "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	h := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(h[:])
	redirectURI := "https://chatgpt.com/connector_platform_oauth_redirect"

	authURL := fmt.Sprintf("%s/authorize?response_type=code&client_id=%s&redirect_uri=%s&code_challenge=%s&code_challenge_method=S256&state=teststate",
		ts.URL, regResp.ClientID, url.QueryEscape(redirectURI), challenge)
	// Don't follow redirects — we want the 302.
	noRedirect := &http.Client{CheckRedirect: func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}}
	authResp, err := noRedirect.Get(authURL)
	if err != nil {
		t.Fatal(err)
	}
	authResp.Body.Close()
	if authResp.StatusCode != http.StatusFound {
		t.Fatalf("authorize: status %d, want 302", authResp.StatusCode)
	}
	loc := authResp.Header.Get("Location")
	code := parseQueryParam(t, loc, "code")
	if code == "" {
		t.Fatal("authorize: no code in redirect")
	}
	if got := parseQueryParam(t, loc, "state"); got != "teststate" {
		t.Fatalf("authorize: state = %q, want %q", got, "teststate")
	}

	// 3. Token: exchange code for access token.
	tokenBody := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"client_id":     {regResp.ClientID},
		"redirect_uri":  {redirectURI},
		"code_verifier": {verifier},
	}
	tokenResp, err := http.PostForm(ts.URL+"/token", tokenBody)
	if err != nil {
		t.Fatal(err)
	}
	defer tokenResp.Body.Close()
	if tokenResp.StatusCode != http.StatusOK {
		t.Fatalf("token: status %d, want 200", tokenResp.StatusCode)
	}
	var tokResp struct {
		AccessToken string `json:"access_token"`
		TokenType   string `json:"token_type"`
		ExpiresIn   int    `json:"expires_in"`
	}
	json.NewDecoder(tokenResp.Body).Decode(&tokResp)
	if tokResp.AccessToken == "" {
		t.Fatal("token: empty access_token")
	}
	if tokResp.TokenType != "Bearer" {
		t.Fatalf("token: type = %q, want Bearer", tokResp.TokenType)
	}

	// 4. Validate the token.
	claims, err := srv.ValidateAccessToken(tokResp.AccessToken)
	if err != nil {
		t.Fatal(err)
	}
	if claims.ClientID != regResp.ClientID {
		t.Errorf("claims.client_id = %q, want %q", claims.ClientID, regResp.ClientID)
	}
}

// TestAuthorizeRejectsBadClient verifies authorize fails for unknown clients.
func TestAuthorizeRejectsBadClient(t *testing.T) {
	st := storetest.Open(t)
	expires := time.Now().Add(time.Hour)
	if err := st.CreateTenantExpiry("q-test", "quick tunnel", &expires); err != nil {
		t.Fatal(err)
	}
	srv, err := oauth.NewServer(st, "http://localhost", "q-test", expires)
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	noRedirect := &http.Client{CheckRedirect: func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}}
	resp, err := noRedirect.Get(ts.URL + "/authorize?response_type=code&client_id=unknown&redirect_uri=https://example.com/cb&code_challenge=abc&code_challenge_method=S256")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("authorize with bad client: status %d, want 302", resp.StatusCode)
	}
	loc := resp.Header.Get("Location")
	if !strings.Contains(loc, "error=invalid_client") {
		t.Fatalf("redirect %q missing error=invalid_client", loc)
	}
}

// TestTokenRejectsReusedCode verifies that an authorization code can only be
// exchanged once.
func TestTokenRejectsReusedCode(t *testing.T) {
	st := storetest.Open(t)
	expires := time.Now().Add(time.Hour)
	if err := st.CreateTenantExpiry("q-test", "quick tunnel", &expires); err != nil {
		t.Fatal(err)
	}
	srv, err := oauth.NewServer(st, "http://localhost", "q-test", expires)
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	// Register + authorize to get a code.
	regBody := `{"redirect_uris":["https://example.com/cb"]}`
	regResp, _ := http.Post(ts.URL+"/register", "application/json", strings.NewReader(regBody))
	var reg struct {
		ClientID string `json:"client_id"`
	}
	json.NewDecoder(regResp.Body).Decode(&reg)
	regResp.Body.Close()

	verifier := "test-verifier-43-chars-long-for-pkce-ok!!"
	h := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(h[:])
	noRedirect := &http.Client{CheckRedirect: func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}}
	authResp, _ := noRedirect.Get(fmt.Sprintf("%s/authorize?response_type=code&client_id=%s&redirect_uri=%s&code_challenge=%s&code_challenge_method=S256",
		ts.URL, reg.ClientID, url.QueryEscape("https://example.com/cb"), challenge))
	authResp.Body.Close()
	code := parseQueryParam(t, authResp.Header.Get("Location"), "code")

	tokenBody := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"client_id":     {reg.ClientID},
		"redirect_uri":  {"https://example.com/cb"},
		"code_verifier": {verifier},
	}

	// First exchange succeeds.
	resp1, _ := http.PostForm(ts.URL+"/token", tokenBody)
	resp1.Body.Close()
	if resp1.StatusCode != http.StatusOK {
		t.Fatalf("first token exchange: status %d, want 200", resp1.StatusCode)
	}

	// Second exchange fails — code is consumed.
	resp2, _ := http.PostForm(ts.URL+"/token", tokenBody)
	resp2.Body.Close()
	if resp2.StatusCode != http.StatusBadRequest {
		t.Fatalf("reused code: status %d, want 400", resp2.StatusCode)
	}
}

func parseQueryParam(t *testing.T, rawURL, key string) string {
	t.Helper()
	u, err := url.Parse(rawURL)
	if err != nil {
		t.Fatalf("parse redirect URL %q: %v", rawURL, err)
	}
	return u.Query().Get(key)
}

// TestAuthorizePasswordGate verifies that when the service has a password,
// the authorize endpoint requires it: no password → HTML form; wrong password
// → form with error; correct password → redirect with code.
func TestAuthorizePasswordGate(t *testing.T) {
	st := storetest.Open(t)
	expires := time.Now().Add(time.Hour)
	if err := st.CreateTenantExpiry("q-pw", "quick tunnel", &expires); err != nil {
		t.Fatal(err)
	}

	// Create the "mcp" service with a password.
	hash, err := store.HashSecret("secret123")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.CreateService("q-pw", &store.Service{
		Name: "mcp", AuthMode: "oauth", PasswordHash: hash,
	}); err != nil {
		t.Fatal(err)
	}

	srv, err := oauth.NewServer(st, "http://localhost", "q-pw", expires)
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	// Register a client.
	regResp, _ := http.Post(ts.URL+"/register", "application/json",
		strings.NewReader(`{"redirect_uris":["https://example.com/cb"]}`))
	var reg struct {
		ClientID string `json:"client_id"`
	}
	json.NewDecoder(regResp.Body).Decode(&reg)
	regResp.Body.Close()

	verifier := "test-verifier-43-chars-long-for-pkce-ok!!"
	h := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(h[:])
	authParams := fmt.Sprintf("response_type=code&client_id=%s&redirect_uri=%s&code_challenge=%s&code_challenge_method=S256",
		reg.ClientID, url.QueryEscape("https://example.com/cb"), challenge)

	noRedirect := &http.Client{CheckRedirect: func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}}

	// No password → 200 with password form.
	resp, err := noRedirect.Get(ts.URL + "/authorize?" + authParams)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("no password: status %d, want 200 (form)", resp.StatusCode)
	}

	// Wrong password → 200 with error.
	resp, err = noRedirect.PostForm(ts.URL+"/authorize", url.Values{
		"client_id":             {reg.ClientID},
		"redirect_uri":          {"https://example.com/cb"},
		"response_type":         {"code"},
		"code_challenge":        {challenge},
		"code_challenge_method": {"S256"},
		"password":              {"wrong"},
	})
	if err != nil {
		t.Fatal(err)
	}
	body := make([]byte, 4096)
	n, _ := resp.Body.Read(body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("wrong password: status %d, want 200 (form)", resp.StatusCode)
	}
	if !strings.Contains(string(body[:n]), "Wrong password") {
		t.Fatal("wrong password: response missing error message")
	}

	// Correct password → 302 with code.
	resp, err = noRedirect.PostForm(ts.URL+"/authorize", url.Values{
		"client_id":             {reg.ClientID},
		"redirect_uri":          {"https://example.com/cb"},
		"response_type":         {"code"},
		"code_challenge":        {challenge},
		"code_challenge_method": {"S256"},
		"password":              {"secret123"},
	})
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("correct password: status %d, want 302", resp.StatusCode)
	}
	code := parseQueryParam(t, resp.Header.Get("Location"), "code")
	if code == "" {
		t.Fatal("correct password: no code in redirect")
	}
}
