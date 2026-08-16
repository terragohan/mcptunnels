package oauth

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"html/template"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/generalpiston/openai-tunnel-oauth/internal/store"
)

// authCodeTTL is the lifetime of an authorization code (OAuth 2.1: short).
const authCodeTTL = 60 * time.Second

// authzParams carries the validated /authorize request parameters.
type authzParams struct {
	ClientID      string
	ClientName    string
	RedirectURI   string
	State         string
	Scope         string
	CodeChallenge string
	Resource      string
}

// validateAuthorize checks the authorization request. On failure it returns
// an error plus a boolean reporting whether the redirect_uri was validated —
// per RFC 6749 §4.1.2.1 errors may only be redirected to a validated URI.
// r.ParseForm must have been called (handlers do) so both GET query and POST
// form parameters are considered.
func (s *Server) validateAuthorize(r *http.Request) (*authzParams, bool, error) {
	q := r.Form

	p := &authzParams{
		ClientID:      q.Get("client_id"),
		RedirectURI:   q.Get("redirect_uri"),
		State:         q.Get("state"),
		Scope:         q.Get("scope"),
		CodeChallenge: q.Get("code_challenge"),
		Resource:      q.Get("resource"),
	}

	if q.Get("response_type") != "code" {
		return nil, false, errors.New("response_type must be \"code\"")
	}
	client, err := s.store.GetClient(s.tenantSlug, p.ClientID)
	if errors.Is(err, store.ErrNotFound) {
		return nil, false, errors.New("unknown client_id")
	}
	if err != nil {
		return nil, false, err
	}
	if !redirectURIRegistered(client, p.RedirectURI) {
		return nil, false, errors.New("redirect_uri does not match a registered URI")
	}
	if !s.redirectHostAllowed(p.RedirectURI) {
		return nil, false, errors.New("redirect_uri host is not allowed on this server")
	}
	// From here on the redirect target is trusted.
	p.ClientName = client.ClientName
	if p.ClientName == "" {
		p.ClientName = p.ClientID
	}
	if p.CodeChallenge == "" {
		return p, true, errors.New("code_challenge is required")
	}
	if method := q.Get("code_challenge_method"); method != "S256" {
		return p, true, errors.New("code_challenge_method must be S256")
	}
	return p, true, nil
}

// handleAuthorizeGet validates the request, then starts the appropriate
// identity flow: upstream IdP picker (or an auto-redirect when exactly one
// provider is configured), or the dev password login.
func (s *Server) handleAuthorizeGet(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	p, redirectOK, err := s.validateAuthorize(r)
	if err != nil {
		s.authorizeError(w, r, p, redirectOK, err)
		return
	}
	if s.broker.HasProviders() {
		names := s.broker.Names()
		if len(names) == 1 {
			http.Redirect(w, r, s.prefix+"/idp/"+names[0]+"/login?"+r.URL.RawQuery, http.StatusFound)
			return
		}
		s.renderPicker(w, names, r.URL.RawQuery)
		return
	}
	s.renderLogin(w, r, p, "")
}

// handleAuthorizePost handles the dev login form: it validates the request
// (params are re-submitted as hidden form fields), checks the dev password,
// and moves on to the consent screen.
func (s *Server) handleAuthorizePost(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	p, redirectOK, err := s.validateAuthorize(r)
	if err != nil {
		s.authorizeError(w, r, p, redirectOK, err)
		return
	}

	password := r.PostForm.Get("password")
	// A tenant with its own login password (issued at signup) must use it;
	// the global dev_auth password is only the fallback for tenants without
	// one.
	ok := false
	if s.store != nil {
		match, hasPassword, err := s.store.VerifyTenantLogin(s.tenantSlug, password)
		if err == nil {
			if hasPassword {
				ok = match
			} else {
				ok = s.devPassword != "" && subtle.ConstantTimeCompare([]byte(password), []byte(s.devPassword)) == 1
			}
		}
	} else if s.devPassword != "" {
		ok = subtle.ConstantTimeCompare([]byte(password), []byte(s.devPassword)) == 1
	}
	if !ok {
		s.renderLogin(w, r, p, "Incorrect password.")
		return
	}

	s.startConsent(w, r, p, s.devUsername, "")
}

// startConsent records the authenticated identity alongside the validated
// authorize params (single-use, short TTL) and renders the consent page.
func (s *Server) startConsent(w http.ResponseWriter, r *http.Request, p *authzParams, subject, email string) {
	consentID := randomString(32)
	payload, err := json.Marshal(pendingAuth{Params: p, Subject: subject, Email: email})
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if err := s.store.InsertAuthRequest(s.tenantSlug, consentID, kindConsent, payload, time.Now().Add(authRequestTTL)); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	s.renderConsent(w, r, consentID, p, subject, email)
}

// handleConsentPost consumes the consent record: Approve issues the
// authorization code, Deny redirects with access_denied (RFC 6749 §4.1.2.1).
func (s *Server) handleConsentPost(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	pa, ok := s.consumePending(w, r.PostForm.Get("consent_id"), kindConsent)
	if !ok {
		return
	}

	if r.PostForm.Get("action") != "approve" {
		s.audit("authorize_denied", pa.Subject, pa.Params.ClientID, "", clientIP(r), nil)
		target, _ := url.Parse(pa.Params.RedirectURI)
		q := target.Query()
		q.Set("error", "access_denied")
		if pa.Params.State != "" {
			q.Set("state", pa.Params.State)
		}
		target.RawQuery = q.Encode()
		http.Redirect(w, r, target.String(), http.StatusFound)
		return
	}
	s.audit("authorize_approved", pa.Subject, pa.Params.ClientID, "", clientIP(r), map[string]string{
		"scope":    pa.Params.Scope,
		"resource": pa.Params.Resource,
	})
	s.issueCode(w, r, pa.Params, pa.Subject, pa.Email)
}

// issueCode creates a one-time authorization code and redirects to the
// client's redirect_uri with code+state.
func (s *Server) issueCode(w http.ResponseWriter, r *http.Request, p *authzParams, subject, email string) {
	code := randomString(32)
	ac := &store.AuthCode{
		Code:          code,
		ClientID:      p.ClientID,
		RedirectURI:   p.RedirectURI,
		CodeChallenge: p.CodeChallenge,
		Scope:         p.Scope,
		Resource:      p.Resource,
		Subject:       subject,
		Email:         email,
		ExpiresAt:     time.Now().Add(authCodeTTL),
	}
	if err := s.store.InsertAuthCode(s.tenantSlug, ac); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	target, _ := url.Parse(p.RedirectURI)
	q := target.Query()
	q.Set("code", code)
	if p.State != "" {
		q.Set("state", p.State)
	}
	target.RawQuery = q.Encode()
	http.Redirect(w, r, target.String(), http.StatusFound)
}

// authorizeError reports an authorization failure: redirect per RFC 6749
// §4.1.2.1 when the redirect_uri was validated, otherwise a plain 400 page.
func (s *Server) authorizeError(w http.ResponseWriter, r *http.Request, p *authzParams, redirectOK bool, cause error) {
	if redirectOK && p != nil {
		target, _ := url.Parse(p.RedirectURI)
		q := target.Query()
		q.Set("error", "invalid_request")
		q.Set("error_description", cause.Error())
		if p.State != "" {
			q.Set("state", p.State)
		}
		target.RawQuery = q.Encode()
		http.Redirect(w, r, target.String(), http.StatusFound)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusBadRequest)
	_ = errorPage.Execute(w, map[string]string{"Error": cause.Error()})
}

var errorPage = template.Must(template.New("error").Parse(`<!doctype html>
<html><head><meta charset="utf-8"><title>Authorization error</title></head>
<body style="font-family:system-ui;max-width:26rem;margin:4rem auto;padding:0 1rem">
<h1>Authorization error</h1>
<p>{{.Error}}</p>
</body></html>`))

type loginPageData struct {
	ClientName string
	Username   string
	Scopes     []string
	Error      string
	Prefix     string      // URL prefix for the form action ("" or /t/{tenant})
	Hidden     [][2]string // hidden form fields preserving the authz request
}

func (s *Server) renderLogin(w http.ResponseWriter, r *http.Request, p *authzParams, errMsg string) {
	q := r.Form
	hidden := [][2]string{
		{"response_type", q.Get("response_type")},
		{"client_id", p.ClientID},
		{"redirect_uri", p.RedirectURI},
		{"state", p.State},
		{"scope", p.Scope},
		{"code_challenge", p.CodeChallenge},
		{"code_challenge_method", q.Get("code_challenge_method")},
		{"resource", p.Resource},
	}
	data := loginPageData{
		ClientName: p.ClientName,
		Username:   s.devUsername,
		Scopes:     strings.Fields(p.Scope),
		Error:      errMsg,
		Prefix:     s.prefix,
		Hidden:     hidden,
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = loginPage.Execute(w, data)
}

var loginPage = template.Must(template.New("login").Parse(`<!doctype html>
<html><head><meta charset="utf-8"><title>Authorize — tunneld</title></head>
<body style="font-family:system-ui;max-width:26rem;margin:4rem auto;padding:0 1rem">
<h1>Authorize {{.ClientName}}</h1>
<p><strong>{{.ClientName}}</strong> requests access to your services as <strong>{{.Username}}</strong>.</p>
{{if .Scopes}}<p>Requested scopes:</p><ul>{{range .Scopes}}<li><code>{{.}}</code></li>{{end}}</ul>{{end}}
{{if .Error}}<p style="color:#b00020">{{.Error}}</p>{{end}}
<form method="post" action="{{.Prefix}}/authorize">
{{range .Hidden}}<input type="hidden" name="{{index . 0}}" value="{{index . 1}}">
{{end}}<p><input type="password" name="password" placeholder="Password" autocomplete="current-password" autofocus required style="width:100%;padding:.5rem"></p>
<p><button type="submit" style="padding:.5rem 1rem">Sign in &amp; authorize</button></p>
</form>
</body></html>`))

// verifyPKCE checks an RFC 7636 S256 code verifier against the stored
// challenge.
func verifyPKCE(verifier, challenge string) bool {
	if verifier == "" || challenge == "" {
		return false
	}
	sum := sha256.Sum256([]byte(verifier))
	got := base64.RawURLEncoding.EncodeToString(sum[:])
	return subtle.ConstantTimeCompare([]byte(got), []byte(challenge)) == 1
}
