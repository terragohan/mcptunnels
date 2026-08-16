package idp

import (
	"testing"

	"github.com/generalpiston/openai-tunnel-oauth/internal/config"
)

func TestEmailAllowed(t *testing.T) {
	cases := []struct {
		name    string
		cfg     config.IdPProvider
		email   string
		allowed bool
	}{
		{"no allowlists allows anyone", config.IdPProvider{}, "anyone@example.com", true},
		{"no allowlists allows empty", config.IdPProvider{}, "", true},
		{"email on list", config.IdPProvider{AllowedEmails: []string{"a@example.com"}}, "a@example.com", true},
		{"email not on list", config.IdPProvider{AllowedEmails: []string{"a@example.com"}}, "b@example.com", false},
		{"domain allowed", config.IdPProvider{AllowedDomains: []string{"example.com"}}, "whoever@example.com", true},
		{"domain not allowed", config.IdPProvider{AllowedDomains: []string{"example.com"}}, "whoever@other.com", false},
		{"subdomain is not the domain", config.IdPProvider{AllowedDomains: []string{"example.com"}}, "x@sub.example.com", false},
		{"email list wins over domain miss", config.IdPProvider{
			AllowedEmails:  []string{"friend@other.com"},
			AllowedDomains: []string{"example.com"},
		}, "friend@other.com", true},
		{"malformed email rejected", config.IdPProvider{AllowedDomains: []string{"example.com"}}, "no-at-sign", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := &Provider{cfg: tc.cfg}
			if got := p.EmailAllowed(tc.email); got != tc.allowed {
				t.Errorf("EmailAllowed(%q) = %v, want %v", tc.email, got, tc.allowed)
			}
		})
	}
}
