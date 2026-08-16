package proxy_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jwt"

	"github.com/generalpiston/openai-tunnel-oauth/internal/proxy"
	"github.com/generalpiston/openai-tunnel-oauth/internal/store"
)

// fakeOIDC is an in-process OIDC provider for tests: it serves discovery +
// JWKS, auto-approves every authorize request, and issues signed ID tokens.
type fakeOIDC struct {
	t       *testing.T
	srv     *httptest.Server
	privJWK jwk.Key
	pubSet  jwk.Set
	email   string
}

func newFakeOIDC(t *testing.T, email string) *fakeOIDC {
	t.Helper()
	f := &fakeOIDC{t: t, email: email}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	privJWK, err := jwk.FromRaw(key)
	if err != nil {
		t.Fatal(err)
	}
	if err := privJWK.Set(jwk.KeyIDKey, "fake-key-1"); err != nil {
		t.Fatal(err)
	}
	if err := privJWK.Set(jwk.AlgorithmKey, jwa.ES256); err != nil {
		t.Fatal(err)
	}
	pubJWK, err := privJWK.PublicKey()
	if err != nil {
		t.Fatal(err)
	}
	f.privJWK = privJWK
	f.pubSet = jwk.NewSet()
	f.pubSet.AddKey(pubJWK)

	mux := http.NewServeMux()
	mux.HandleFunc("GET /.well-known/openid-configuration", f.handleDiscovery)
	mux.HandleFunc("GET /authorize", f.handleAuthorize)
	mux.HandleFunc("POST /token", f.handleToken)
	mux.HandleFunc("GET /jwks", f.handleJWKS)
	f.srv = httptest.NewServer(mux)
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeOIDC) handleDiscovery(w http.ResponseWriter, _ *http.Request) {
	json.NewEncoder(w).Encode(map[string]any{
		"issuer":                 f.srv.URL,
		"authorization_endpoint": f.srv.URL + "/authorize",
		"token_endpoint":         f.srv.URL + "/token",
		"jwks_uri":               f.srv.URL + "/jwks",
	})
}

// handleAuthorize auto-approves: straight back to the redirect_uri.
func (f *fakeOIDC) handleAuthorize(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	target, err := url.Parse(q.Get("redirect_uri"))
	if err != nil {
		f.t.Errorf("fake idp: bad redirect_uri: %v", err)
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	out := target.Query()
	out.Set("code", "fake-upstream-code")
	out.Set("state", q.Get("state"))
	target.RawQuery = out.Encode()
	http.Redirect(w, r, target.String(), http.StatusFound)
}

func (f *fakeOIDC) handleToken(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	now := time.Now()
	tok, err := jwt.NewBuilder().
		Issuer(f.srv.URL).
		Subject("user-42").
		Audience([]string{"fake-client"}).
		IssuedAt(now).
		Expiration(now.Add(time.Hour)).
		Claim("email", f.email).
		Claim("email_verified", true).
		Build()
	if err != nil {
		f.t.Errorf("fake idp: build id_token: %v", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	signed, err := jwt.Sign(tok, jwt.WithKey(jwa.ES256, f.privJWK))
	if err != nil {
		f.t.Errorf("fake idp: sign id_token: %v", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"access_token": "fake-access-token",
		"token_type":   "Bearer",
		"expires_in":   3600,
		"id_token":     string(signed),
	})
}

func (f *fakeOIDC) handleJWKS(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(f.pubSet)
}

// setupM3 brings up the multi-tenant tunneld with tenant acme configured with
// a fake OIDC provider (via the store, as `mcptunnel idp set` would).
func setupM3(t *testing.T, idpEmail string, allowedDomains []string) *mtEnv {
	t.Helper()
	fake := newFakeOIDC(t, idpEmail)
	return setupMT(t, map[string][]store.IDPConfig{
		"acme": {{
			Name:           "fake",
			ClientID:       "fake-client",
			ClientSecret:   "fake-secret",
			Issuer:         fake.srv.URL,
			AllowedDomains: allowedDomains,
		}},
	})
}

// followRedirect issues a GET to the Location of a 3xx response, resolving
// relative Locations against the original request URL.
func followRedirect(t *testing.T, resp *http.Response) *http.Response {
	t.Helper()
	loc := resp.Header.Get("Location")
	if loc == "" {
		t.Fatalf("expected redirect, got status %d", resp.StatusCode)
	}
	ref, err := url.Parse(loc)
	if err != nil {
		t.Fatal(err)
	}
	next, err := noRedirectClient.Get(resp.Request.URL.ResolveReference(ref).String())
	if err != nil {
		t.Fatal(err)
	}
	return next
}

func TestM3OIDCFlowAndIdentityHeaders(t *testing.T) {
	e := setupM3(t, "user@example.com", []string{"example.com"})
	c := e.oauth("acme")
	resource := e.tenantIssuer("acme") + "/s/demo"

	clientID := c.register(chatgptRedirect)

	// --- /authorize: single provider → auto-redirect to /t/acme/idp/fake/login ---
	authzQuery := url.Values{
		"response_type":         {"code"},
		"client_id":             {clientID},
		"redirect_uri":          {chatgptRedirect},
		"state":                 {"state-xyz"},
		"scope":                 {"read write"},
		"code_challenge":        {pkceChallenge()},
		"code_challenge_method": {"S256"},
		"resource":              {resource},
	}
	resp, err := noRedirectClient.Get(c.url("/authorize") + "?" + authzQuery.Encode())
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if loc := resp.Header.Get("Location"); !strings.HasPrefix(loc, "/t/acme/idp/fake/login?") {
		t.Fatalf("authorize: Location %q, want /t/acme/idp/fake/login?...", loc)
	}

	// --- IdP login → upstream authorize → auto-approve → tunneld callback ---
	resp = followRedirect(t, resp) // → fake provider /authorize
	resp.Body.Close()
	resp = followRedirect(t, resp) // → tunneld /t/acme/idp/fake/callback
	resp.Body.Close()
	resp = followRedirect(t, resp) // → consent page
	page, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("callback: status %d, want consent page; page %.300s", resp.StatusCode, page)
	}
	if !strings.Contains(string(page), "user@example.com") {
		t.Fatalf("callback: want consent page with identity; page %.300s", page)
	}
	consentID := extractConsentID(t, page)

	// --- consent approve → code ---
	resp, err = noRedirectClient.PostForm(c.url("/authorize/consent"), url.Values{
		"consent_id": {consentID},
		"action":     {"approve"},
	})
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("consent: status %d, want 302", resp.StatusCode)
	}
	loc, err := url.Parse(resp.Header.Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	code := loc.Query().Get("code")
	if code == "" || loc.Query().Get("state") != "state-xyz" {
		t.Fatalf("bad redirect %q", loc)
	}

	// --- code exchange → JWT with email claim ---
	accessToken, _ := c.exchange(clientID, chatgptRedirect, code)

	parsed, err := jwt.ParseString(accessToken, jwt.WithKeySet(e.jwks("acme")), jwt.WithValidate(true))
	if err != nil {
		t.Fatalf("access token does not verify: %v", err)
	}
	if parsed.Issuer() != e.tenantIssuer("acme") {
		t.Errorf("iss = %q, want %q", parsed.Issuer(), e.tenantIssuer("acme"))
	}
	if parsed.Subject() != "fake:user-42" {
		t.Errorf("sub = %q, want fake:user-42", parsed.Subject())
	}
	if parsed.PrivateClaims()["email"] != "user@example.com" {
		t.Errorf("email claim = %v, want user@example.com", parsed.PrivateClaims()["email"])
	}

	// --- tunneled call: backend receives signed identity headers ---
	req, _ := http.NewRequest(http.MethodGet, e.tenantIssuer("acme")+"/s/demo/echo", nil)
	req.Header.Set("Authorization", "Bearer "+accessToken)
	resp, err = noRedirectClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("tunneled call: status %d: %s", resp.StatusCode, body)
	}
	echo := string(body)
	for _, want := range []string{
		"subject=fake:user-42",
		"email=user@example.com",
		"scopes=read write",
		"clientid=" + clientID,
	} {
		if !strings.Contains(echo, want) {
			t.Errorf("upstream echo missing %q: %s", want, echo)
		}
	}
	wantSig := proxy.SignIdentity("svc-secret", "fake:user-42", "user@example.com", "read write", clientID)
	if !strings.Contains(echo, "sig="+wantSig) {
		t.Errorf("HMAC mismatch: echo %s, want sig=%s", echo, wantSig)
	}
}
