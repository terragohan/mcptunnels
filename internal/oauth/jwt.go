package oauth

import (
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwt"
)

// AccessClaims are the validated claims of an access token issued by this AS.
type AccessClaims struct {
	Subject   string
	Email     string
	ClientID  string
	Scope     string
	Audience  []string
	ExpiresAt time.Time
}

// signAccessToken issues an ES256 JWT. aud is the RFC 8707 resource if given,
// else the issuer. The email claim is included when non-empty.
func (s *Server) signAccessToken(subject, email, clientID, scope, resource string) (string, error) {
	aud := resource
	if aud == "" {
		aud = s.issuer
	}
	now := time.Now()
	b := jwt.NewBuilder().
		Issuer(s.issuer).
		Subject(subject).
		Audience([]string{aud}).
		IssuedAt(now).
		Expiration(now.Add(s.accessTokenTTL)).
		JwtID(randomString(16)).
		Claim("client_id", clientID).
		Claim("scope", scope)
	if email != "" {
		b = b.Claim("email", email)
	}
	tok, err := b.Build()
	if err != nil {
		return "", err
	}
	signed, err := jwt.Sign(tok, jwt.WithKey(jwa.ES256, s.privJWK))
	if err != nil {
		return "", err
	}
	return string(signed), nil
}

// ValidateAccessToken verifies the signature (via the local key), expiry, and
// issuer of a bearer token. It is used by the public proxy to gate /s/*.
func (s *Server) ValidateAccessToken(tokenStr string) (*AccessClaims, error) {
	if tokenStr == "" {
		return nil, errors.New("oauth: empty token")
	}
	tok, err := jwt.ParseString(tokenStr,
		jwt.WithKey(jwa.ES256, s.pubJWK),
		jwt.WithValidate(true),
	)
	if err != nil {
		return nil, fmt.Errorf("oauth: invalid token: %w", err)
	}
	if tok.Issuer() != s.issuer {
		return nil, errors.New("oauth: issuer mismatch")
	}
	claims := &AccessClaims{
		Subject:   tok.Subject(),
		Audience:  tok.Audience(),
		ExpiresAt: tok.Expiration(),
	}
	priv := tok.PrivateClaims()
	if v, ok := priv["client_id"].(string); ok {
		claims.ClientID = v
	}
	if v, ok := priv["email"].(string); ok {
		claims.Email = v
	}
	if v, ok := priv["scope"].(string); ok {
		claims.Scope = v
	}
	return claims, nil
}

// handleJWKS serves the public JWK set (RFC 7517).
func (s *Server) handleJWKS(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Cache-Control", "public, max-age=300")
	writeJSON(w, http.StatusOK, s.pubSet)
}
