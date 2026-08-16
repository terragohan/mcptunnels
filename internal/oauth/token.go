package oauth

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"time"

	"github.com/generalpiston/openai-tunnel-oauth/internal/store"
)

// tokenResponse is the RFC 6749 §5.1 successful token response.
type tokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int64  `json:"expires_in"`
	RefreshToken string `json:"refresh_token,omitempty"`
	Scope        string `json:"scope,omitempty"`
}

// handleToken dispatches on grant_type.
func (s *Server) handleToken(w http.ResponseWriter, r *http.Request) {
	if !s.tokenLimiter.allow(clientIP(r)) {
		writeTokenError(w, http.StatusTooManyRequests, "too_many_requests", "token rate limit exceeded")
		return
	}
	if err := r.ParseForm(); err != nil {
		writeTokenError(w, http.StatusBadRequest, "invalid_request", "malformed form body")
		return
	}
	switch r.PostForm.Get("grant_type") {
	case "authorization_code":
		s.exchangeAuthCode(w, r)
	case "refresh_token":
		s.refreshGrant(w, r)
	default:
		writeTokenError(w, http.StatusBadRequest, "unsupported_grant_type", "grant_type must be authorization_code or refresh_token")
	}
}

func (s *Server) exchangeAuthCode(w http.ResponseWriter, r *http.Request) {
	code := r.PostForm.Get("code")
	clientID := r.PostForm.Get("client_id")
	redirectURI := r.PostForm.Get("redirect_uri")
	verifier := r.PostForm.Get("code_verifier")
	if code == "" || clientID == "" || verifier == "" {
		writeTokenError(w, http.StatusBadRequest, "invalid_request", "code, client_id and code_verifier are required")
		return
	}

	fail := func(desc string) {
		writeTokenError(w, http.StatusBadRequest, "invalid_grant", desc)
	}

	ac, err := s.store.GetAuthCode(s.tenantSlug, code)
	if errors.Is(err, store.ErrNotFound) {
		fail("unknown authorization code")
		return
	}
	if err != nil {
		writeTokenError(w, http.StatusInternalServerError, "server_error", "store failure")
		return
	}
	switch {
	case ac.UsedAt != nil:
		fail("authorization code already used")
	case time.Now().After(ac.ExpiresAt):
		fail("authorization code expired")
	case ac.ClientID != clientID:
		fail("client_id mismatch")
	case ac.RedirectURI != redirectURI:
		fail("redirect_uri mismatch")
	case !verifyPKCE(verifier, ac.CodeChallenge):
		fail("PKCE verification failed")
	default:
		// Atomically consume the code; a concurrent replay loses the race.
		ok, err := s.store.MarkAuthCodeUsed(s.tenantSlug, code, time.Now())
		if err != nil {
			writeTokenError(w, http.StatusInternalServerError, "server_error", "store failure")
			return
		}
		if !ok {
			fail("authorization code already used")
			return
		}
		s.audit("token_issued", ac.Subject, ac.ClientID, "", clientIP(r), map[string]string{
			"grant_type": "authorization_code",
			"resource":   ac.Resource,
		})
		s.issueTokens(w, ac.ClientID, ac.Subject, ac.Email, ac.Scope, ac.Resource)
		return
	}
}

func (s *Server) refreshGrant(w http.ResponseWriter, r *http.Request) {
	token := r.PostForm.Get("refresh_token")
	clientID := r.PostForm.Get("client_id")
	if token == "" || clientID == "" {
		writeTokenError(w, http.StatusBadRequest, "invalid_request", "refresh_token and client_id are required")
		return
	}

	fail := func(desc string) {
		writeTokenError(w, http.StatusBadRequest, "invalid_grant", desc)
	}

	hash := hashToken(token)
	rt, err := s.store.GetRefreshToken(s.tenantSlug, hash)
	if errors.Is(err, store.ErrNotFound) {
		fail("unknown refresh token")
		return
	}
	if err != nil {
		writeTokenError(w, http.StatusInternalServerError, "server_error", "store failure")
		return
	}
	switch {
	case rt.RevokedAt != nil:
		fail("refresh token revoked")
	case rt.RotatedTo != nil:
		// Reuse of an already-rotated token: possible theft — revoke the
		// whole chain descended from it.
		_ = s.store.RevokeRefreshChain(s.tenantSlug, hash, time.Now())
		s.audit("refresh_reuse_detected", rt.Subject, rt.ClientID, "", clientIP(r), nil)
		fail("refresh token reuse detected; token chain revoked")
	case time.Now().After(rt.ExpiresAt):
		fail("refresh token expired")
	case rt.ClientID != clientID:
		fail("client_id mismatch")
	default:
		newToken := randomString(32)
		newRT := &store.RefreshToken{
			TokenHash: hashToken(newToken),
			ClientID:  rt.ClientID,
			Subject:   rt.Subject,
			Email:     rt.Email,
			Scope:     rt.Scope,
			Resource:  rt.Resource,
			ExpiresAt: time.Now().Add(s.refreshTokenTTL),
		}
		if err := s.store.InsertRefreshToken(s.tenantSlug, newRT); err != nil {
			writeTokenError(w, http.StatusInternalServerError, "server_error", "store failure")
			return
		}
		ok, err := s.store.RotateRefreshToken(s.tenantSlug, hash, newRT.TokenHash, time.Now())
		if err != nil {
			writeTokenError(w, http.StatusInternalServerError, "server_error", "store failure")
			return
		}
		if !ok {
			// Lost a race against another rotation: reuse.
			_ = s.store.RevokeRefreshChain(s.tenantSlug, hash, time.Now())
			s.audit("refresh_reuse_detected", rt.Subject, rt.ClientID, "", clientIP(r), nil)
			fail("refresh token reuse detected; token chain revoked")
			return
		}
		s.audit("token_refreshed", rt.Subject, rt.ClientID, "", clientIP(r), map[string]string{
			"resource": rt.Resource,
		})
		s.writeTokenResponse(w, rt.ClientID, rt.Subject, rt.Email, rt.Scope, rt.Resource, newToken)
		return
	}
}

// issueTokens creates an access token + refresh token pair and writes the
// token response.
func (s *Server) issueTokens(w http.ResponseWriter, clientID, subject, email, scope, resource string) {
	refreshToken := randomString(32)
	rt := &store.RefreshToken{
		TokenHash: hashToken(refreshToken),
		ClientID:  clientID,
		Subject:   subject,
		Email:     email,
		Scope:     scope,
		Resource:  resource,
		ExpiresAt: time.Now().Add(s.refreshTokenTTL),
	}
	if err := s.store.InsertRefreshToken(s.tenantSlug, rt); err != nil {
		writeTokenError(w, http.StatusInternalServerError, "server_error", "store failure")
		return
	}
	s.writeTokenResponse(w, clientID, subject, email, scope, resource, refreshToken)
}

func (s *Server) writeTokenResponse(w http.ResponseWriter, clientID, subject, email, scope, resource, refreshToken string) {
	accessToken, err := s.signAccessToken(subject, email, clientID, scope, resource)
	if err != nil {
		writeTokenError(w, http.StatusInternalServerError, "server_error", "could not sign access token")
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	writeJSON(w, http.StatusOK, tokenResponse{
		AccessToken:  accessToken,
		TokenType:    "Bearer",
		ExpiresIn:    int64(s.accessTokenTTL / time.Second),
		RefreshToken: refreshToken,
		Scope:        scope,
	})
}

// writeTokenError writes an RFC 6749 §5.2 error response.
func writeTokenError(w http.ResponseWriter, status int, code, desc string) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	writeJSONError(w, status, code, desc)
}

func writeJSONError(w http.ResponseWriter, status int, code, desc string) {
	writeJSON(w, status, map[string]string{
		"error":             code,
		"error_description": desc,
	})
}

// hashToken returns the storage form of an opaque token (SHA-256, hex).
func hashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}
