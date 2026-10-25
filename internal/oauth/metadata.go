package oauth

import (
	"encoding/json"
	"net/http"
)

// asMetadata returns the RFC 8414 authorization-server metadata document.
func (s *Server) asMetadata(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"issuer":                                s.issuer,
		"authorization_endpoint":                s.issuer + "/authorize",
		"token_endpoint":                        s.issuer + "/token",
		"registration_endpoint":                 s.issuer + "/register",
		"jwks_uri":                              s.issuer + "/jwks.json",
		"response_types_supported":              []string{"code"},
		"grant_types_supported":                 []string{"authorization_code"},
		"code_challenge_methods_supported":      []string{"S256"},
		"token_endpoint_auth_methods_supported": []string{"none"},
		"scopes_supported":                      []string{"mcp"},
	})
}

// resourceMetadata returns the RFC 9728 protected-resource metadata document
// for a service path under this tenant.
func (s *Server) resourceMetadata(w http.ResponseWriter, r *http.Request) {
	// The resource URL is the full request path minus the well-known prefix.
	// e.g. /.well-known/oauth-protected-resource/t/q-xxx/s/mcp
	//    → resource = https://host/t/q-xxx/s/mcp
	resource := s.baseURL + r.URL.Path[len("/.well-known/oauth-protected-resource"):]
	writeJSON(w, http.StatusOK, map[string]any{
		"resource":                 resource,
		"authorization_servers":    []string{s.issuer},
		"bearer_methods_supported": []string{"header"},
	})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, status int, errCode, desc string) {
	writeJSON(w, status, map[string]string{
		"error":             errCode,
		"error_description": desc,
	})
}
