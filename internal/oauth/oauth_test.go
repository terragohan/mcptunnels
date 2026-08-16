package oauth

import (
	"crypto/sha256"
	"encoding/base64"
	"net/url"
	"testing"
	"time"
)

func TestVerifyPKCE(t *testing.T) {
	verifier := "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	sum := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(sum[:])

	if !verifyPKCE(verifier, challenge) {
		t.Error("valid verifier rejected")
	}
	if verifyPKCE("wrong", challenge) {
		t.Error("wrong verifier accepted")
	}
	if verifyPKCE("", challenge) {
		t.Error("empty verifier accepted")
	}
	if verifyPKCE(verifier, "") {
		t.Error("empty challenge accepted")
	}
	// Challenge must be compared exactly (a verifier that hashes to a
	// different encoding must fail).
	if verifyPKCE(verifier, challenge+"A") {
		t.Error("mangled challenge accepted")
	}
}

func TestIPLimiter(t *testing.T) {
	l := newIPLimiter(10, time.Minute)
	for i := 0; i < 10; i++ {
		if !l.allow("1.2.3.4") {
			t.Fatalf("request %d denied, want allowed (burst 10)", i+1)
		}
	}
	if l.allow("1.2.3.4") {
		t.Error("11th request allowed, want denied")
	}
	// Other IPs are unaffected.
	if !l.allow("5.6.7.8") {
		t.Error("other IP denied")
	}
}

func TestIsLoopbackRedirect(t *testing.T) {
	ok := []string{
		"http://127.0.0.1:8973/cb", "http://127.34.0.9/cb",
		"http://localhost/cb", "http://localhost:51123/oauth/callback",
		"http://[::1]:8080/cb", "http://[::ffff:127.0.0.1]/cb", // 4-in-6 mapped loopback
	}
	for _, u := range ok {
		p, _ := url.Parse(u)
		if !isLoopbackRedirect(p) {
			t.Errorf("%s: want loopback=true", u)
		}
	}
	bad := []string{
		"https://127.0.0.1/cb", "http://example.com/cb", "http://10.0.0.4/cb",
		"http://192.168.1.5/cb",
		"ftp://127.0.0.1/cb", "http://localhost.evil.com/cb",
	}
	for _, u := range bad {
		p, _ := url.Parse(u)
		if isLoopbackRedirect(p) {
			t.Errorf("%s: want loopback=false", u)
		}
	}
}
