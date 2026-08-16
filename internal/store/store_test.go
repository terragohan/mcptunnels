package store_test

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/generalpiston/openai-tunnel-oauth/internal/store"
	"github.com/generalpiston/openai-tunnel-oauth/internal/store/storetest"
)

func TestTenantTokens(t *testing.T) {
	st := storetest.Open(t)

	if err := st.CreateTenant("acme", "Acme Inc"); err != nil {
		t.Fatal(err)
	}
	if err := st.CreateTenant("acme", ""); !errors.Is(err, store.ErrExists) {
		t.Fatalf("duplicate tenant: %v, want ErrExists", err)
	}

	tok, err := st.CreateTenantToken("acme")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(tok, "tun_ten_") {
		t.Fatalf("token %q lacks tun_ten_ prefix", tok)
	}
	slug, isOp, err := st.ValidateToken(tok)
	if err != nil {
		t.Fatal(err)
	}
	if slug != "acme" || isOp {
		t.Fatalf("ValidateToken = (%q, %v), want (acme, false)", slug, isOp)
	}
	if _, _, err := st.ValidateToken("tun_ten_" + tok[8:len(tok)-2] + "xx"); !errors.Is(err, store.ErrInvalidToken) {
		t.Fatalf("tampered token: %v, want ErrInvalidToken", err)
	}

	// Rotation revokes the old token immediately.
	tok2, err := st.RotateTenantToken("acme")
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := st.ValidateToken(tok); !errors.Is(err, store.ErrInvalidToken) {
		t.Fatalf("old token after rotate: %v, want ErrInvalidToken", err)
	}
	if _, _, err := st.ValidateToken(tok2); err != nil {
		t.Fatalf("new token after rotate: %v", err)
	}

	// Deleting the tenant cascades to its tokens.
	if ok, err := st.DeleteTenant("acme"); !ok || err != nil {
		t.Fatalf("DeleteTenant = (%v, %v)", ok, err)
	}
	if _, _, err := st.ValidateToken(tok2); !errors.Is(err, store.ErrInvalidToken) {
		t.Fatalf("token of deleted tenant: %v, want ErrInvalidToken", err)
	}
}

func TestOperatorAndSetupTokens(t *testing.T) {
	st := storetest.Open(t)

	if has, err := st.HasOperatorTokens(); err != nil || has {
		t.Fatalf("HasOperatorTokens = (%v, %v), want (false, nil)", has, err)
	}
	op, err := st.CreateOperatorToken()
	if err != nil {
		t.Fatal(err)
	}
	if has, _ := st.HasOperatorTokens(); !has {
		t.Fatal("HasOperatorTokens = false after CreateOperatorToken")
	}
	slug, isOp, err := st.ValidateToken(op)
	if err != nil {
		t.Fatal(err)
	}
	if slug != "" || !isOp {
		t.Fatalf("ValidateToken = (%q, %v), want (\"\", true)", slug, isOp)
	}

	setup, err := st.CreateSetupToken()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(setup, "tun_setup_") {
		t.Fatalf("setup token %q lacks tun_setup_ prefix", setup)
	}
	ok, err := st.ConsumeSetupToken(setup)
	if err != nil || !ok {
		t.Fatalf("ConsumeSetupToken = (%v, %v), want (true, nil)", ok, err)
	}
	// One-time: a second consume fails.
	if ok, err := st.ConsumeSetupToken(setup); err != nil || ok {
		t.Fatalf("second ConsumeSetupToken = (%v, %v), want (false, nil)", ok, err)
	}
	if ok, err := st.ConsumeSetupToken("tun_setup_bogus"); err != nil || ok {
		t.Fatalf("bogus ConsumeSetupToken = (%v, %v), want (false, nil)", ok, err)
	}
}

func TestServicesAndAgentKeys(t *testing.T) {
	st := storetest.Open(t)
	if err := st.CreateTenant("acme", ""); err != nil {
		t.Fatal(err)
	}

	if _, err := st.CreateService("nope", &store.Service{Name: "demo"}); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("CreateService on missing tenant: %v, want ErrNotFound", err)
	}

	key, err := st.CreateService("acme", &store.Service{Name: "demo", AuthMode: "discovery_open"})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(key, "tun_agent_") {
		t.Fatalf("agent key %q lacks tun_agent_ prefix", key)
	}
	if _, err := st.CreateService("acme", &store.Service{Name: "demo"}); !errors.Is(err, store.ErrExists) {
		t.Fatalf("duplicate service: %v, want ErrExists", err)
	}

	svc, err := st.ValidateAgentKey("acme", "demo", key)
	if err != nil {
		t.Fatal(err)
	}
	if svc.Name != "demo" || svc.AuthMode != "discovery_open" {
		t.Fatalf("ValidateAgentKey returned %+v", svc)
	}
	if _, err := st.ValidateAgentKey("acme", "demo", "tun_agent_wrong"); !errors.Is(err, store.ErrInvalidAgentKey) {
		t.Fatalf("wrong key: %v, want ErrInvalidAgentKey", err)
	}
	if _, err := st.ValidateAgentKey("acme", "other", key); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("unknown service: %v, want ErrNotFound", err)
	}

	key2, err := st.RotateAgentKey("acme", "demo")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.ValidateAgentKey("acme", "demo", key); !errors.Is(err, store.ErrInvalidAgentKey) {
		t.Fatalf("old key after rotate: %v, want ErrInvalidAgentKey", err)
	}
	if _, err := st.ValidateAgentKey("acme", "demo", key2); err != nil {
		t.Fatalf("new key after rotate: %v", err)
	}

	// Deleting the tenant cascades to its services.
	if _, err := st.CreateService("acme", &store.Service{Name: "gone"}); err != nil {
		t.Fatal(err)
	}
	if ok, err := st.DeleteTenant("acme"); !ok || err != nil {
		t.Fatalf("DeleteTenant = (%v, %v)", ok, err)
	}
	if _, err := st.GetService("acme", "gone"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("service of deleted tenant: %v, want ErrNotFound", err)
	}
}

func TestIDPAndAudit(t *testing.T) {
	st := storetest.Open(t)
	if err := st.CreateTenant("acme", ""); err != nil {
		t.Fatal(err)
	}

	cfg := &store.IDPConfig{
		Name:           "google",
		ClientID:       "id",
		ClientSecret:   "secret",
		Issuer:         "https://accounts.google.com",
		AllowedDomains: []string{"acme.com"},
	}
	if err := st.SetIDP("acme", cfg); err != nil {
		t.Fatal(err)
	}
	cfg.ClientID = "id2" // upsert
	if err := st.SetIDP("acme", cfg); err != nil {
		t.Fatal(err)
	}
	cfgs, err := st.ListIDP("acme")
	if err != nil {
		t.Fatal(err)
	}
	if len(cfgs) != 1 || cfgs[0].ClientID != "id2" || len(cfgs[0].AllowedDomains) != 1 {
		t.Fatalf("ListIDP = %+v", cfgs)
	}
	if ok, err := st.DeleteIDP("acme", "google"); !ok || err != nil {
		t.Fatalf("DeleteIDP = (%v, %v)", ok, err)
	}
	if ok, _ := st.DeleteIDP("acme", "google"); ok {
		t.Fatal("second DeleteIDP = true, want false")
	}

	if err := st.LogAudit("acme", store.AuditEntry{Event: "service.created", Service: "demo"}); err != nil {
		t.Fatal(err)
	}
	entries, err := st.ListAudit("acme", 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Event != "service.created" || entries[0].Detail != "{}" {
		t.Fatalf("ListAudit = %+v", entries)
	}
}

func TestTenantIsolation(t *testing.T) {
	st := storetest.Open(t)
	for _, slug := range []string{"a", "b"} {
		if err := st.CreateTenant(slug, ""); err != nil {
			t.Fatal(err)
		}
	}
	if err := st.InsertClient("a", &store.Client{
		ClientID:     "c1",
		RedirectURIs: []string{"https://x/cb"},
		GrantTypes:   []string{"authorization_code"},
		CreatedAt:    time.Now(),
	}); err != nil {
		t.Fatal(err)
	}
	// Same client_id under another tenant is a different row.
	if _, err := st.GetClient("b", "c1"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("GetClient cross-tenant: %v, want ErrNotFound", err)
	}
}

func TestInvites(t *testing.T) {
	st := storetest.Open(t)
	code, err := st.CreateInvite()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(code, "mcp_invite_") {
		t.Fatalf("invite %q lacks mcp_invite_ prefix", code)
	}
	if ok, err := st.ConsumeInvite("mcp_invite_bogus"); err != nil || ok {
		t.Fatalf("bogus invite: ok=%v err=%v, want false,nil", ok, err)
	}
	if ok, err := st.ConsumeInvite(code); err != nil || !ok {
		t.Fatalf("consume: ok=%v err=%v, want true,nil", ok, err)
	}
	// Single-use.
	if ok, err := st.ConsumeInvite(code); err != nil || ok {
		t.Fatalf("re-consume: ok=%v err=%v, want false,nil", ok, err)
	}
}

func TestTenantLoginPassword(t *testing.T) {
	st := storetest.Open(t)
	if err := st.CreateTenant("acme", ""); err != nil {
		t.Fatal(err)
	}
	// No password set: verify reports hasPassword=false.
	if ok, has, err := st.VerifyTenantLogin("acme", "x"); err != nil || ok || has {
		t.Fatalf("no password: ok=%v has=%v err=%v, want false,false,nil", ok, has, err)
	}
	// Unknown tenant: ErrNotFound.
	if _, _, err := st.VerifyTenantLogin("nope", "x"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("unknown tenant: %v, want ErrNotFound", err)
	}
	pw := store.NewLoginPassword()
	if !strings.HasPrefix(pw, "mcp_pass_") {
		t.Fatalf("password %q lacks prefix", pw)
	}
	if err := st.SetTenantLoginPassword("acme", pw); err != nil {
		t.Fatal(err)
	}
	if ok, has, _ := st.VerifyTenantLogin("acme", pw); !ok || !has {
		t.Fatal("correct password rejected")
	}
	if ok, has, _ := st.VerifyTenantLogin("acme", "wrong"); ok || !has {
		t.Fatal("wrong password accepted")
	}
	// Reset replaces.
	if err := st.SetTenantLoginPassword("acme", "mcp_pass_new"); err != nil {
		t.Fatal(err)
	}
	if ok, _, _ := st.VerifyTenantLogin("acme", pw); ok {
		t.Fatal("old password still works after reset")
	}
	if err := st.SetTenantLoginPassword("nope", "x"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("set on unknown tenant: %v, want ErrNotFound", err)
	}
}
