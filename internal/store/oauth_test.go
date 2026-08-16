package store_test

import (
	"errors"
	"testing"
	"time"

	"github.com/terragohan/mcptunnels/internal/store"
	"github.com/terragohan/mcptunnels/internal/store/storetest"
)

func TestSigningKeyRoundTrip(t *testing.T) {
	st := storetest.Open(t)
	if err := st.CreateTenant("q-key", ""); err != nil {
		t.Fatal(err)
	}
	pem := "-----BEGIN EC PRIVATE KEY-----\nfake\n-----END EC PRIVATE KEY-----"
	if err := st.CreateSigningKey("q-key", pem); err != nil {
		t.Fatal(err)
	}
	got, err := st.GetSigningKey("q-key")
	if err != nil {
		t.Fatal(err)
	}
	if got != pem {
		t.Fatalf("signing key = %q, want %q", got, pem)
	}

	// INSERT OR IGNORE: second create is a no-op.
	if err := st.CreateSigningKey("q-key", "other"); err != nil {
		t.Fatal(err)
	}
	got, _ = st.GetSigningKey("q-key")
	if got != pem {
		t.Fatalf("after re-create: signing key = %q, want original", got)
	}

	// Unknown tenant.
	if _, err := st.GetSigningKey("q-nope"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("missing tenant: %v, want ErrNotFound", err)
	}

	// Cascade: deleting the tenant removes the key.
	if _, err := st.DeleteTenant("q-key"); err != nil {
		t.Fatal(err)
	}
	if _, err := st.GetSigningKey("q-key"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("after cascade: %v, want ErrNotFound", err)
	}
}

func TestOAuthClientRoundTrip(t *testing.T) {
	st := storetest.Open(t)
	if err := st.CreateTenant("q-cli", ""); err != nil {
		t.Fatal(err)
	}
	uris := `["https://example.com/cb","http://localhost:3000/cb"]`
	if err := st.CreateOAuthClient("q-cli", "client1", uris); err != nil {
		t.Fatal(err)
	}
	got, err := st.GetOAuthClient("q-cli", "client1")
	if err != nil {
		t.Fatal(err)
	}
	if got != uris {
		t.Fatalf("redirect_uris = %q, want %q", got, uris)
	}

	// Duplicate.
	if err := st.CreateOAuthClient("q-cli", "client1", uris); !errors.Is(err, store.ErrExists) {
		t.Fatalf("duplicate: %v, want ErrExists", err)
	}

	// Unknown.
	if _, err := st.GetOAuthClient("q-cli", "nope"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("unknown client: %v, want ErrNotFound", err)
	}
}

func TestAuthCodeLifecycle(t *testing.T) {
	st := storetest.Open(t)
	if err := st.CreateTenant("q-code", ""); err != nil {
		t.Fatal(err)
	}
	expires := time.Now().Add(time.Minute)
	if err := st.CreateAuthCode("hash1", "q-code", "client1", "https://example.com/cb", "challenge1", expires); err != nil {
		t.Fatal(err)
	}

	// Consume succeeds.
	tenant, clientID, redirectURI, challenge, err := st.ConsumeAuthCode("hash1", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if tenant != "q-code" || clientID != "client1" || redirectURI != "https://example.com/cb" || challenge != "challenge1" {
		t.Fatalf("ConsumeAuthCode = (%q, %q, %q, %q)", tenant, clientID, redirectURI, challenge)
	}

	// Second consume fails — already used.
	if _, _, _, _, err := st.ConsumeAuthCode("hash1", time.Now()); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("reused code: %v, want ErrNotFound", err)
	}

	// Expired code.
	expired := time.Now().Add(-time.Minute)
	if err := st.CreateAuthCode("hash2", "q-code", "client1", "https://example.com/cb", "ch", expired); err != nil {
		t.Fatal(err)
	}
	if _, _, _, _, err := st.ConsumeAuthCode("hash2", time.Now()); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("expired code: %v, want ErrNotFound", err)
	}

	// Unknown code.
	if _, _, _, _, err := st.ConsumeAuthCode("nope", time.Now()); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("unknown code: %v, want ErrNotFound", err)
	}
}

func TestServiceAuthMode(t *testing.T) {
	st := storetest.Open(t)
	if err := st.CreateTenant("q-mode", ""); err != nil {
		t.Fatal(err)
	}

	// Default: oauth.
	if _, err := st.CreateService("q-mode", &store.Service{Name: "default"}); err != nil {
		t.Fatal(err)
	}
	svc, err := st.GetService("q-mode", "default")
	if err != nil {
		t.Fatal(err)
	}
	if svc.AuthMode != "oauth" {
		t.Fatalf("default auth_mode = %q, want %q", svc.AuthMode, "oauth")
	}

	// Explicit open.
	if _, err := st.CreateService("q-mode", &store.Service{Name: "open", AuthMode: "open"}); err != nil {
		t.Fatal(err)
	}
	svc, err = st.GetService("q-mode", "open")
	if err != nil {
		t.Fatal(err)
	}
	if svc.AuthMode != "open" {
		t.Fatalf("explicit auth_mode = %q, want %q", svc.AuthMode, "open")
	}
}
