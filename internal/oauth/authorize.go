package oauth

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"html"
	"net/http"
	"net/url"
	"time"
)

// authCodeTTL is how long an authorization code lives before it can no longer
// be exchanged.
const authCodeTTL = 60 * time.Second

// handleAuthorize validates the authorization request. When the service has a
// password, GET renders a password form and POST validates it. On success
// (correct password or no password), auto-approves and redirects to
// redirect_uri with a one-time authorization code. PKCE S256 is mandatory.
func (s *Server) handleAuthorize(w http.ResponseWriter, r *http.Request) {
	// Params arrive in the query for GET and in the form body for POST (the
	// password form re-submits them as hidden fields); FormValue covers both.
	clientID := r.FormValue("client_id")
	redirectURI := r.FormValue("redirect_uri")
	responseType := r.FormValue("response_type")
	codeChallenge := r.FormValue("code_challenge")
	codeChallengeMethod := r.FormValue("code_challenge_method")
	state := r.FormValue("state")

	if responseType != "code" {
		s.authError(w, r, redirectURI, state, "unsupported_response_type", "only response_type=code is supported")
		return
	}
	if codeChallenge == "" || codeChallengeMethod != "S256" {
		s.authError(w, r, redirectURI, state, "invalid_request", "PKCE S256 code_challenge is required")
		return
	}

	// Validate the client exists and the redirect_uri matches registration.
	urisJSON, err := s.store.GetOAuthClient(s.tenant, clientID)
	if err != nil {
		s.authError(w, r, redirectURI, state, "invalid_client", "unknown client_id")
		return
	}
	var registeredURIs []string
	if err := json.Unmarshal([]byte(urisJSON), &registeredURIs); err != nil {
		s.authError(w, r, redirectURI, state, "server_error", "corrupt client registration")
		return
	}
	if !containsString(registeredURIs, redirectURI) {
		s.authError(w, r, redirectURI, state, "invalid_request", "redirect_uri does not match registration")
		return
	}

	// Password gate: quick tunnels protect the authorize endpoint with a
	// password the CLI generates and prints. No password → render the form.
	// Wrong password → re-render with an error.
	if s.hasPassword() {
		password := r.FormValue("password")
		ok, err := s.store.ValidatePassword(s.tenant, "mcp", password)
		if err != nil || !ok {
			s.renderPasswordForm(w, r, password != "")
			return
		}
	}

	// Auto-approve: issue a one-time authorization code.
	code := hex.EncodeToString(mustRand(32))
	codeHash := sha256hex(code)
	expiresAt := time.Now().Add(authCodeTTL)
	if err := s.store.CreateAuthCode(codeHash, s.tenant, clientID, redirectURI, codeChallenge, expiresAt); err != nil {
		s.authError(w, r, redirectURI, state, "server_error", "failed to create authorization code")
		return
	}

	u, _ := url.Parse(redirectURI)
	vals := u.Query()
	vals.Set("code", code)
	if state != "" {
		vals.Set("state", state)
	}
	u.RawQuery = vals.Encode()
	http.Redirect(w, r, u.String(), http.StatusFound)
}

// hasPassword reports whether the tenant's "mcp" service has an authorize
// password set.
func (s *Server) hasPassword() bool {
	svc, err := s.store.GetService(s.tenant, "mcp")
	return err == nil && svc.PasswordHash != ""
}

// renderPasswordForm serves a minimal HTML password prompt. The form
// re-submits all OAuth params as hidden fields plus the password.
func (s *Server) renderPasswordForm(w http.ResponseWriter, r *http.Request, failed bool) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	errMsg := ""
	if failed {
		errMsg = `<p style="color:red">Wrong password.</p>`
	}
	fmt.Fprintf(w, `<!DOCTYPE html>
<html><head><title>Authorize — mcptunnels</title>
<style>body{font-family:system-ui;max-width:400px;margin:80px auto;padding:0 16px}
input[type=password]{width:100%%;padding:8px;margin:8px 0;font-size:16px}
button{padding:8px 24px;font-size:16px}</style></head>
<body><h2>Authorize access</h2>
<p>Enter the password shown by <code>mcptunnel expose</code>.</p>
%s
<form method="post">
<input type="hidden" name="client_id" value="%s">
<input type="hidden" name="redirect_uri" value="%s">
<input type="hidden" name="response_type" value="%s">
<input type="hidden" name="code_challenge" value="%s">
<input type="hidden" name="code_challenge_method" value="%s">
<input type="hidden" name="state" value="%s">
<input type="password" name="password" placeholder="Password" autofocus required>
<br><button type="submit">Authorize</button>
</form></body></html>`,
		errMsg,
		html.EscapeString(r.FormValue("client_id")),
		html.EscapeString(r.FormValue("redirect_uri")),
		html.EscapeString(r.FormValue("response_type")),
		html.EscapeString(r.FormValue("code_challenge")),
		html.EscapeString(r.FormValue("code_challenge_method")),
		html.EscapeString(r.FormValue("state")),
	)
}

// authError redirects back to the client with an OAuth error, or renders a
// plain error when redirect_uri is missing/untrusted.
func (s *Server) authError(w http.ResponseWriter, r *http.Request, redirectURI, state, errCode, desc string) {
	if redirectURI == "" {
		writeErr(w, http.StatusBadRequest, errCode, desc)
		return
	}
	u, err := url.Parse(redirectURI)
	if err != nil {
		writeErr(w, http.StatusBadRequest, errCode, desc)
		return
	}
	vals := u.Query()
	vals.Set("error", errCode)
	vals.Set("error_description", desc)
	if state != "" {
		vals.Set("state", state)
	}
	u.RawQuery = vals.Encode()
	http.Redirect(w, r, u.String(), http.StatusFound)
}

func containsString(haystack []string, needle string) bool {
	for _, s := range haystack {
		if s == needle {
			return true
		}
	}
	return false
}

func sha256hex(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}
