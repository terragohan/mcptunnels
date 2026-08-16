package oauth

import (
	"crypto/sha256"
	"encoding/base64"
	"net/http"
	"time"
)

// tokenRateLimit is the per-remote-IP cap on token requests per hour.
const tokenRateLimit = 60

// tokenRate tracks per-IP token request counts in fixed one-hour windows.
var tokenRate = newIPRate()

// handleToken implements POST /token with grant_type=authorization_code.
// Validates the code, client, redirect_uri, and PKCE verifier, then issues an
// ES256 JWT access token. No refresh tokens — tunnels are ephemeral.
func (s *Server) handleToken(w http.ResponseWriter, r *http.Request) {
	if !tokenRate.allow(clientIP(r), tokenRateLimit) {
		writeErr(w, http.StatusTooManyRequests, "rate_limited", "too many token requests; try again later")
		return
	}
	if err := r.ParseForm(); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid_request", "malformed form body")
		return
	}
	if r.PostForm.Get("grant_type") != "authorization_code" {
		writeErr(w, http.StatusBadRequest, "unsupported_grant_type", "only authorization_code is supported")
		return
	}

	code := r.PostForm.Get("code")
	clientID := r.PostForm.Get("client_id")
	redirectURI := r.PostForm.Get("redirect_uri")
	codeVerifier := r.PostForm.Get("code_verifier")

	if code == "" || clientID == "" || codeVerifier == "" {
		writeErr(w, http.StatusBadRequest, "invalid_request", "code, client_id, and code_verifier are required")
		return
	}

	// Consume the code atomically — single use, not expired.
	codeHash := sha256hex(code)
	storedTenant, storedClientID, storedRedirectURI, storedChallenge, err := s.store.ConsumeAuthCode(codeHash, time.Now())
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid_grant", "authorization code is invalid, expired, or already used")
		return
	}
	if storedTenant != s.tenant || storedClientID != clientID || storedRedirectURI != redirectURI {
		writeErr(w, http.StatusBadRequest, "invalid_grant", "code does not match client or redirect_uri")
		return
	}

	// Verify PKCE: BASE64URL(SHA256(code_verifier)) == stored code_challenge
	// (RFC 7636 §4.6).
	if !verifyPKCE(codeVerifier, storedChallenge) {
		writeErr(w, http.StatusBadRequest, "invalid_grant", "PKCE verification failed")
		return
	}

	// Issue the access token. TTL = remaining tunnel TTL.
	expiresAt := s.tenantExpiresAt()
	token, err := signAccessToken(s.signingKey, s.issuer, "quick-tunnel", clientID, "mcp", "", expiresAt)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "server_error", "failed to sign token")
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"access_token": token,
		"token_type":   "Bearer",
		"expires_in":   int(time.Until(expiresAt).Seconds()),
		"scope":        "mcp",
	})
}

// verifyPKCE checks that BASE64URL(SHA256(verifier)) == challenge.
func verifyPKCE(verifier, challenge string) bool {
	h := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(h[:]) == challenge
}
