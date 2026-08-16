package proxy_test

import (
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
)

// TestTenantLoginPassword verifies per-tenant OAuth login passwords: a tenant
// with its own password logs in with it (and NOT with the global dev
// password); a tenant without one still uses the global dev password.
func TestTenantLoginPassword(t *testing.T) {
	e := setupMT(t, nil)
	const tenantPassword = "mcp_pass_abc123"
	if err := e.store.SetTenantLoginPassword("acme", tenantPassword); err != nil {
		t.Fatal(err)
	}

	redirectURI := "https://chatgpt.com/connector_platform_oauth_redirect"

	// acme: the tenant password completes the full flow.
	c := e.oauth("acme")
	clientID := c.register(redirectURI)
	code := c.authorizeWithPassword(clientID, redirectURI, "", tenantPassword)
	access, _ := c.exchange(clientID, redirectURI, code)
	if access == "" {
		t.Fatal("no access token after tenant-password login")
	}

	// acme: the global dev password no longer works.
	if loggedIn(t, c, clientID, redirectURI, "test-password") {
		t.Fatal("global dev password accepted for a tenant with its own password")
	}

	// globex (no per-tenant password): the global dev password still works.
	g := e.oauth("globex")
	if !loggedIn(t, g, g.register(redirectURI), redirectURI, "test-password") {
		t.Fatal("global dev password rejected for a tenant without its own password")
	}
}

// loggedIn reports whether a login POST with password reaches the consent
// page (a rejected login re-renders the login form instead).
func loggedIn(t *testing.T, c *oauthClient, clientID, redirectURI, password string) bool {
	t.Helper()
	q := url.Values{
		"response_type":         {"code"},
		"client_id":             {clientID},
		"redirect_uri":          {redirectURI},
		"state":                 {"s"},
		"code_challenge":        {pkceChallenge()},
		"code_challenge_method": {"S256"},
		"password":              {password},
	}
	resp, err := noRedirectClient.PostForm(c.url("/authorize"), q)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	page, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("login POST: status %d", resp.StatusCode)
	}
	return strings.Contains(string(page), "Approve")
}
