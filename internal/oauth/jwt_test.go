package oauth

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"
	"time"
)

func testKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func TestJWTRoundTrip(t *testing.T) {
	key := testKey(t)
	issuer := "https://tunnel.example.com/t/q-test"
	expires := time.Now().Add(time.Hour).Truncate(time.Second)

	token, err := signAccessToken(key, issuer, "quick-tunnel", "client123", "mcp", "", expires)
	if err != nil {
		t.Fatal(err)
	}

	claims, err := validateAccessToken(&key.PublicKey, issuer, token)
	if err != nil {
		t.Fatal(err)
	}
	if claims.Issuer != issuer {
		t.Errorf("issuer = %q, want %q", claims.Issuer, issuer)
	}
	if claims.Subject != "quick-tunnel" {
		t.Errorf("subject = %q, want %q", claims.Subject, "quick-tunnel")
	}
	if claims.ClientID != "client123" {
		t.Errorf("client_id = %q, want %q", claims.ClientID, "client123")
	}
	if !claims.ExpiresAt.Equal(expires) {
		t.Errorf("expires = %v, want %v", claims.ExpiresAt, expires)
	}
}

func TestJWTExpired(t *testing.T) {
	key := testKey(t)
	issuer := "https://tunnel.example.com/t/q-test"
	token, err := signAccessToken(key, issuer, "sub", "cid", "mcp", "", time.Now().Add(-time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := validateAccessToken(&key.PublicKey, issuer, token); err == nil {
		t.Fatal("expected error for expired token")
	}
}

func TestJWTWrongIssuer(t *testing.T) {
	key := testKey(t)
	token, err := signAccessToken(key, "https://other.example.com/t/q-a", "sub", "cid", "mcp", "", time.Now().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := validateAccessToken(&key.PublicKey, "https://tunnel.example.com/t/q-b", token); err == nil {
		t.Fatal("expected error for wrong issuer")
	}
}

func TestJWTWrongKey(t *testing.T) {
	key1, key2 := testKey(t), testKey(t)
	issuer := "https://tunnel.example.com/t/q-test"
	token, err := signAccessToken(key1, issuer, "sub", "cid", "mcp", "", time.Now().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := validateAccessToken(&key2.PublicKey, issuer, token); err == nil {
		t.Fatal("expected error for wrong key")
	}
}

func TestJWTMalformed(t *testing.T) {
	key := testKey(t)
	for _, token := range []string{"", "a", "a.b", "a.b.c.d"} {
		if _, err := validateAccessToken(&key.PublicKey, "iss", token); err == nil {
			t.Errorf("expected error for %q", token)
		}
	}
}

func TestGenerateKeyRoundTrip(t *testing.T) {
	pemStr, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	key, err := parseKey(pemStr)
	if err != nil {
		t.Fatal(err)
	}
	issuer := "https://tunnel.example.com/t/q-test"
	token, err := signAccessToken(key, issuer, "sub", "cid", "mcp", "", time.Now().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := validateAccessToken(&key.PublicKey, issuer, token); err != nil {
		t.Fatal(err)
	}
}

func TestVerifyPKCE(t *testing.T) {
	// RFC 7636 Appendix B test vector.
	verifier := "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	challenge := "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
	if !verifyPKCE(verifier, challenge) {
		t.Fatal("PKCE verification failed for RFC 7636 test vector")
	}
	if verifyPKCE("wrong-verifier", challenge) {
		t.Fatal("PKCE verification succeeded for wrong verifier")
	}
}
