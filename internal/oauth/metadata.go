package oauth

import (
	"encoding/json"
	"net/http"
	"strings"
)

// metadataDoc is the RFC 8414 authorization-server metadata document.
type metadataDoc struct {
	Issuer                            string   `json:"issuer"`
	AuthorizationEndpoint             string   `json:"authorization_endpoint"`
	TokenEndpoint                     string   `json:"token_endpoint"`
	RegistrationEndpoint              string   `json:"registration_endpoint"`
	JWKSURI                           string   `json:"jwks_uri"`
	ResponseTypesSupported            []string `json:"response_types_supported"`
	GrantTypesSupported               []string `json:"grant_types_supported"`
	CodeChallengeMethodsSupported     []string `json:"code_challenge_methods_supported"`
	TokenEndpointAuthMethodsSupported []string `json:"token_endpoint_auth_methods_supported"`
	ScopesSupported                   []string `json:"scopes_supported,omitempty"`
}

func (s *Server) handleMetadata(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, metadataDoc{
		Issuer:                            s.issuer,
		AuthorizationEndpoint:             s.issuer + "/authorize",
		TokenEndpoint:                     s.issuer + "/token",
		RegistrationEndpoint:              s.issuer + "/register",
		JWKSURI:                           s.issuer + "/jwks.json",
		ResponseTypesSupported:            []string{"code"},
		GrantTypesSupported:               []string{"authorization_code", "refresh_token"},
		CodeChallengeMethodsSupported:     []string{"S256"},
		TokenEndpointAuthMethodsSupported: []string{"none"},
		ScopesSupported:                   s.scopes,
	})
}

// protectedResourceDoc is the RFC 9728 protected-resource metadata document.
type protectedResourceDoc struct {
	Resource             string   `json:"resource"`
	AuthorizationServers []string `json:"authorization_servers"`
}

// handleProtectedResource serves both the root form
// (/.well-known/oauth-protected-resource) and the path-suffix form
// (/.well-known/oauth-protected-resource/s/demo): with a suffix, the
// resource identifier is issuer + suffix.
func (s *Server) handleProtectedResource(w http.ResponseWriter, r *http.Request) {
	resource := s.issuer
	if suffix, ok := strings.CutPrefix(r.URL.Path, "/.well-known/oauth-protected-resource"); ok && suffix != "" {
		resource = s.issuer + suffix
	}
	writeJSON(w, http.StatusOK, protectedResourceDoc{
		Resource:             resource,
		AuthorizationServers: []string{s.issuer},
	})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(v)
}
