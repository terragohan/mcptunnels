package oauth

import (
	"encoding/json"
	"errors"
	"html/template"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/generalpiston/openai-tunnel-oauth/internal/idp"
	"github.com/generalpiston/openai-tunnel-oauth/internal/store"
)

// authRequestTTL is the lifetime of a pending broker/consent request.
const authRequestTTL = 10 * time.Minute

// Kinds of pending authorization requests stored via the store.
const (
	kindIdpLogin = "idp-login"
	kindConsent  = "consent"
)

// pendingAuth is the JSON payload of a pending authorization request. The
// login phase carries the upstream PKCE verifier; the consent phase carries
// the established identity.
type pendingAuth struct {
	Params   *authzParams `json:"params"`
	Verifier string       `json:"verifier,omitempty"`
	Subject  string       `json:"subject,omitempty"`
	Email    string       `json:"email,omitempty"`
}

// consumePending fetches and deletes a pending request of the expected kind,
// writing a 400 error page and reporting false on any failure.
func (s *Server) consumePending(w http.ResponseWriter, state, wantKind string) (*pendingAuth, bool) {
	fail := func(msg string) (*pendingAuth, bool) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusBadRequest)
		_ = errorPage.Execute(w, map[string]string{"Error": msg})
		return nil, false
	}
	kind, payload, err := s.store.ConsumeAuthRequest(s.tenantSlug, state)
	if errors.Is(err, store.ErrNotFound) {
		return fail("Authorization request is unknown or expired. Please start over.")
	}
	if err != nil {
		return fail("Internal error.")
	}
	if kind != wantKind {
		return fail("Unexpected authorization state. Please start over.")
	}
	var pa pendingAuth
	if err := json.Unmarshal(payload, &pa); err != nil || pa.Params == nil {
		return fail("Corrupt authorization state. Please start over.")
	}
	return &pa, true
}

// handleIdpLogin starts the upstream OIDC flow for one provider: it
// re-validates the authorize params, stashes them (plus the upstream PKCE
// verifier) under a random state, and redirects to the provider.
func (s *Server) handleIdpLogin(w http.ResponseWriter, r *http.Request) {
	prov := s.broker.Get(r.PathValue("name"))
	if prov == nil {
		http.NotFound(w, r)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	p, redirectOK, err := s.validateAuthorize(r)
	if err != nil {
		s.authorizeError(w, r, p, redirectOK, err)
		return
	}

	state := randomString(32)
	verifier := randomString(32)
	payload, err := json.Marshal(pendingAuth{Params: p, Verifier: verifier})
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if err := s.store.InsertAuthRequest(s.tenantSlug, state, kindIdpLogin, payload, time.Now().Add(authRequestTTL)); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	authURL, err := prov.AuthCodeURL(r.Context(), s.idpCallbackURL(prov.Name()), state, verifier)
	if err != nil {
		http.Error(w, "identity provider unavailable", http.StatusBadGateway)
		return
	}
	http.Redirect(w, r, authURL, http.StatusFound)
}

// handleIdpCallback completes the upstream OIDC flow: consume the pending
// state, exchange the code, verify the ID token, enforce allowlists, then
// move on to the consent screen.
func (s *Server) handleIdpCallback(w http.ResponseWriter, r *http.Request) {
	prov := s.broker.Get(r.PathValue("name"))
	if prov == nil {
		http.NotFound(w, r)
		return
	}
	q := r.URL.Query()
	if upstreamErr := q.Get("error"); upstreamErr != "" {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusBadRequest)
		_ = errorPage.Execute(w, map[string]string{"Error": "identity provider returned an error: " + upstreamErr})
		return
	}

	pa, ok := s.consumePending(w, q.Get("state"), kindIdpLogin)
	if !ok {
		return
	}

	identity, err := prov.VerifyCallback(r.Context(), s.idpCallbackURL(prov.Name()), q.Get("code"), pa.Verifier)
	if err != nil {
		status := http.StatusBadRequest
		if errors.Is(err, idp.ErrDenied) {
			status = http.StatusForbidden
			s.audit("idp_login_denied", "", pa.Params.ClientID, "", clientIP(r), map[string]string{
				"provider": prov.Name(),
				"reason":   err.Error(),
			})
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(status)
		_ = errorPage.Execute(w, map[string]string{"Error": err.Error()})
		return
	}

	s.startConsent(w, r, pa.Params, identity.Subject, identity.Email)
}

func (s *Server) idpCallbackURL(name string) string {
	return s.issuer + "/idp/" + name + "/callback"
}

// renderPicker shows the provider selection page.
func (s *Server) renderPicker(w http.ResponseWriter, names []string, rawQuery string) {
	links := make([]pickerLink, 0, len(names))
	for _, n := range names {
		links = append(links, pickerLink{
			Name: n,
			URL:  s.prefix + "/idp/" + url.PathEscape(n) + "/login?" + rawQuery,
		})
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = pickerPage.Execute(w, map[string]any{"Links": links})
}

type pickerLink struct {
	Name string
	URL  string
}

var pickerPage = template.Must(template.New("picker").Parse(`<!doctype html>
<html><head><meta charset="utf-8"><title>Sign in — tunneld</title></head>
<body style="font-family:system-ui;max-width:26rem;margin:4rem auto;padding:0 1rem">
<h1>Sign in</h1>
<p>Choose how to authenticate:</p>
<ul>
{{range .Links}}<li style="margin:.5rem 0"><a href="{{.URL}}">Sign in with {{.Name}}</a></li>
{{end}}</ul>
</body></html>`))

// renderConsent shows the consent screen for an established identity.
func (s *Server) renderConsent(w http.ResponseWriter, _ *http.Request, consentID string, p *authzParams, subject, email string) {
	identity := email
	if identity == "" {
		identity = subject
	}
	data := map[string]any{
		"ClientName": p.ClientName,
		"Identity":   identity,
		"Scopes":     strings.Fields(p.Scope),
		"ConsentID":  consentID,
		"Prefix":     s.prefix,
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = consentPage.Execute(w, data)
}

var consentPage = template.Must(template.New("consent").Parse(`<!doctype html>
<html><head><meta charset="utf-8"><title>Authorize — tunneld</title></head>
<body style="font-family:system-ui;max-width:26rem;margin:4rem auto;padding:0 1rem">
<h1>Authorize {{.ClientName}}</h1>
<p><strong>{{.ClientName}}</strong> requests access to your services.</p>
<p>You are signed in as <strong>{{.Identity}}</strong>.</p>
{{if .Scopes}}<p>Requested scopes:</p><ul>{{range .Scopes}}<li><code>{{.}}</code></li>{{end}}</ul>{{end}}
<form method="post" action="{{.Prefix}}/authorize/consent">
<input type="hidden" name="consent_id" value="{{.ConsentID}}">
<p>
<button type="submit" name="action" value="approve" style="padding:.5rem 1rem">Approve</button>
<button type="submit" name="action" value="deny" style="padding:.5rem 1rem">Deny</button>
</p>
</form>
</body></html>`))
