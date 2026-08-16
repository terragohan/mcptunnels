package controlplane_test

import (
	"net/http"
	"testing"

	"github.com/generalpiston/openai-tunnel-oauth/internal/store/storetest"
)

// TestSignupFlow exercises invite-gated self-service signup:
// invite create (operator) → signup → tenant token works → invite is
// single-use → bad invite rejected → slug conflicts don't burn invites.
func TestSignupFlow(t *testing.T) {
	st := storetest.Open(t)
	setupToken, err := st.CreateSetupToken()
	if err != nil {
		t.Fatal(err)
	}
	a := newAPI(t, st)
	var boot struct {
		Token string `json:"token"`
	}
	mustOK(a, "POST", "/bootstrap", map[string]string{"setup_token": setupToken}, &boot)
	a.token = boot.Token

	// Operator mints an invite.
	var inv struct {
		Invite string `json:"invite"`
	}
	mustOK(a, "POST", "/invites", nil, &inv)
	if inv.Invite == "" {
		t.Fatal("empty invite code")
	}

	// Tenant tokens cannot mint invites.
	userAPI := newAPI(t, st)
	userAPI.token = "tun_ten_invalid"
	if code := userAPI.do("POST", "/invites", nil, nil); code != http.StatusUnauthorized {
		t.Fatalf("invite create with bad token: status %d, want 401", code)
	}

	// Signup without an invite → 403; with a bogus invite → 403.
	anon := newAPI(t, st)
	if code := anon.do("POST", "/signup", map[string]string{"slug": "acme"}, nil); code != http.StatusForbidden {
		t.Fatalf("signup without invite: status %d, want 403", code)
	}
	if code := anon.do("POST", "/signup", map[string]string{"slug": "acme", "invite": "mcp_invite_bogus"}, nil); code != http.StatusForbidden {
		t.Fatalf("signup with bogus invite: status %d, want 403", code)
	}

	// Real invite works and returns a usable tenant token plus a login password.
	var su struct {
		Slug     string `json:"slug"`
		Token    string `json:"token"`
		Password string `json:"password"`
	}
	if code := anon.do("POST", "/signup", map[string]string{"slug": "acme", "invite": inv.Invite}, &su); code != http.StatusCreated {
		t.Fatalf("signup: status %d, want 201", code)
	}
	if su.Token == "" || su.Password == "" {
		t.Fatal("signup returned empty token or password")
	}
	anon.token = su.Token
	mustOK(anon, "GET", "/tenants/acme/services", nil, nil)

	// Password reset: tenant can reset its own; the old password dies.
	var pr struct {
		Password string `json:"password"`
	}
	mustOK(anon, "POST", "/tenants/acme/password", nil, &pr)
	if pr.Password == "" || pr.Password == su.Password {
		t.Fatal("password reset did not issue a new password")
	}
	if ok, _, err := st.VerifyTenantLogin("acme", su.Password); err != nil || ok {
		t.Fatal("old password still valid after reset")
	}
	if ok, _, err := st.VerifyTenantLogin("acme", pr.Password); err != nil || !ok {
		t.Fatal("new password rejected")
	}
	// Cross-tenant reset is forbidden.
	other := newAPI(t, st)
	other.token = su.Token
	if code := other.do("POST", "/tenants/other/password", nil, nil); code != http.StatusForbidden {
		t.Fatalf("cross-tenant password reset: status %d, want 403", code)
	}

	// The invite is single-use.
	anon2 := newAPI(t, st)
	if code := anon2.do("POST", "/signup", map[string]string{"slug": "other", "invite": inv.Invite}, nil); code != http.StatusForbidden {
		t.Fatalf("invite reuse: status %d, want 403", code)
	}

	// A slug conflict is detected before the invite is consumed.
	var inv2 struct {
		Invite string `json:"invite"`
	}
	mustOK(a, "POST", "/invites", nil, &inv2)
	if code := anon2.do("POST", "/signup", map[string]string{"slug": "acme", "invite": inv2.Invite}, nil); code != http.StatusConflict {
		t.Fatalf("signup with taken slug: status %d, want 409", code)
	}
	var su2 struct {
		Slug string `json:"slug"`
	}
	if code := anon2.do("POST", "/signup", map[string]string{"slug": "other", "invite": inv2.Invite}, &su2); code != http.StatusCreated {
		t.Fatalf("signup retry after conflict (invite must survive): status %d, want 201", code)
	}
}
