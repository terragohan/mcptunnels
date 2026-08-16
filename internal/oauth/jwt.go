// Package oauth implements a per-tenant OAuth 2.1 authorization server for
// quick tunnels: DCR (RFC 7591), authorization-code flow with PKCE (auto-
// approved, no login/consent), ES256 JWT access tokens, and metadata endpoints
// (RFC 8414, RFC 9728). No refresh tokens — tunnels are ephemeral (24h).
package oauth

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"time"
)

// AccessClaims are the validated claims of an access token issued by this AS.
type AccessClaims struct {
	Issuer    string
	Subject   string
	ClientID  string
	Scope     string
	Audience  []string
	ExpiresAt time.Time
}

// --- key management ---

// GenerateKey creates a new ES256 keypair and returns the PEM-encoded private
// key.
func GenerateKey() (privatePEM string, err error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return "", err
	}
	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return "", err
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der})), nil
}

// parseKey decodes a PEM-encoded EC private key.
func parseKey(privatePEM string) (*ecdsa.PrivateKey, error) {
	block, _ := pem.Decode([]byte(privatePEM))
	if block == nil {
		return nil, errors.New("oauth: invalid PEM")
	}
	return x509.ParseECPrivateKey(block.Bytes)
}

// --- JWT ---

var b64 = base64.RawURLEncoding

// signAccessToken issues an ES256 JWT. aud is the RFC 8707 resource if given,
// else the issuer.
func signAccessToken(key *ecdsa.PrivateKey, issuer, subject, clientID, scope, resource string, expiresAt time.Time) (string, error) {
	aud := resource
	if aud == "" {
		aud = issuer
	}
	header := b64.EncodeToString(mustJSON(map[string]string{"alg": "ES256", "typ": "JWT"}))
	payload := b64.EncodeToString(mustJSON(map[string]any{
		"iss":       issuer,
		"sub":       subject,
		"aud":       aud,
		"exp":       expiresAt.Unix(),
		"iat":       time.Now().Unix(),
		"jti":       fmt.Sprintf("%x", mustRand(16)),
		"client_id": clientID,
		"scope":     scope,
	}))
	input := header + "." + payload
	hash := sha256.Sum256([]byte(input))
	r, s, err := ecdsa.Sign(rand.Reader, key, hash[:])
	if err != nil {
		return "", err
	}
	sig := make([]byte, 64)
	r.FillBytes(sig[:32])
	s.FillBytes(sig[32:])
	return input + "." + b64.EncodeToString(sig), nil
}

// validateAccessToken verifies an ES256 JWT against the given public key:
// signature, expiry, and issuer. No DB lookup — pure local verification.
func validateAccessToken(pub *ecdsa.PublicKey, issuer, tokenString string) (*AccessClaims, error) {
	parts := splitJWT(tokenString)
	if parts == nil {
		return nil, errors.New("oauth: malformed token")
	}
	sig, err := b64.DecodeString(parts[2])
	if err != nil || len(sig) != 64 {
		return nil, errors.New("oauth: bad signature encoding")
	}
	hash := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	r := new(big.Int).SetBytes(sig[:32])
	s := new(big.Int).SetBytes(sig[32:])
	if !ecdsa.Verify(pub, hash[:], r, s) {
		return nil, errors.New("oauth: invalid signature")
	}

	var claims struct {
		Issuer   string `json:"iss"`
		Subject  string `json:"sub"`
		ClientID string `json:"client_id"`
		Scope    string `json:"scope"`
		Aud      any    `json:"aud"` // string or []string
		Exp      int64  `json:"exp"`
	}
	payload, err := b64.DecodeString(parts[1])
	if err != nil {
		return nil, errors.New("oauth: bad payload encoding")
	}
	if err := json.Unmarshal(payload, &claims); err != nil {
		return nil, errors.New("oauth: bad payload JSON")
	}
	if claims.Issuer != issuer {
		return nil, fmt.Errorf("oauth: wrong issuer %q", claims.Issuer)
	}
	if time.Now().Unix() >= claims.Exp {
		return nil, errors.New("oauth: token expired")
	}
	return &AccessClaims{
		Issuer:    claims.Issuer,
		Subject:   claims.Subject,
		ClientID:  claims.ClientID,
		Scope:     claims.Scope,
		Audience:  toStrings(claims.Aud),
		ExpiresAt: time.Unix(claims.Exp, 0),
	}, nil
}

// splitJWT splits "a.b.c" into its three parts, or nil.
func splitJWT(token string) []string {
	var parts []string
	rest := token
	for range 2 {
		i := indexByte(rest, '.')
		if i < 0 {
			return nil
		}
		parts = append(parts, rest[:i])
		rest = rest[i+1:]
	}
	return append(parts, rest)
}

func indexByte(s string, c byte) int {
	for i := range len(s) {
		if s[i] == c {
			return i
		}
	}
	return -1
}

func toStrings(v any) []string {
	switch a := v.(type) {
	case string:
		return []string{a}
	case []any:
		out := make([]string, 0, len(a))
		for _, s := range a {
			if str, ok := s.(string); ok {
				out = append(out, str)
			}
		}
		return out
	}
	return nil
}

func mustJSON(v any) []byte {
	data, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return data
}

func mustRand(n int) []byte {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return b
}

// --- JWKS ---

// jwksHandler serves the public JWK set (RFC 7517).
func jwksHandler(pub *ecdsa.PublicKey) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"keys": []map[string]any{{
				"kty": "EC",
				"crv": "P-256",
				"alg": "ES256",
				"use": "sig",
				"x":   b64.EncodeToString(pub.X.Bytes()),
				"y":   b64.EncodeToString(pub.Y.Bytes()),
			}},
		})
	}
}
