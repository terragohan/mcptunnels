// Package idp brokers user authentication to upstream OIDC identity
// providers (Google, GitHub-via-OIDC, any compliant issuer). tunneld runs an
// authorization-code + PKCE flow against the provider and maps the verified
// upstream identity to a local subject of the form "{provider}:{sub}".
package idp

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"sort"
	"strings"
	"sync"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"

	"github.com/generalpiston/openai-tunnel-oauth/internal/config"
)

// Identity is a verified upstream identity.
type Identity struct {
	// Subject is the local subject: "{provider}:{upstream sub}".
	Subject string
	Email   string
}

// Provider is one configured upstream OIDC provider. Discovery is fetched
// lazily and cached.
type Provider struct {
	cfg config.IdPProvider

	mu       sync.Mutex
	resolved *oidc.Provider
}

// Name returns the provider's config name.
func (p *Provider) Name() string { return p.cfg.Name }

// Broker holds all configured providers.
type Broker struct {
	providers map[string]*Provider
	names     []string // sorted
}

// NewBroker builds a Broker from the configured providers.
func NewBroker(cfgs []config.IdPProvider) *Broker {
	b := &Broker{providers: make(map[string]*Provider, len(cfgs))}
	for _, cfg := range cfgs {
		b.providers[cfg.Name] = &Provider{cfg: cfg}
		b.names = append(b.names, cfg.Name)
	}
	sort.Strings(b.names)
	return b
}

// Names returns the sorted provider names.
func (b *Broker) Names() []string { return b.names }

// HasProviders reports whether any upstream provider is configured.
func (b *Broker) HasProviders() bool { return b != nil && len(b.names) > 0 }

// Get returns the named provider, or nil.
func (b *Broker) Get(name string) *Provider {
	if b == nil {
		return nil
	}
	return b.providers[name]
}

func (p *Provider) discover(ctx context.Context) (*oidc.Provider, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.resolved != nil {
		return p.resolved, nil
	}
	prov, err := oidc.NewProvider(ctx, p.cfg.Issuer)
	if err != nil {
		return nil, fmt.Errorf("idp %s: discovery failed: %w", p.cfg.Name, err)
	}
	p.resolved = prov
	return prov, nil
}

func (p *Provider) oauth2Config(prov *oidc.Provider, redirectURL string) *oauth2.Config {
	return &oauth2.Config{
		ClientID:     p.cfg.ClientID,
		ClientSecret: p.cfg.ClientSecret,
		Endpoint:     prov.Endpoint(),
		RedirectURL:  redirectURL,
		Scopes:       []string{oidc.ScopeOpenID, "email"},
	}
}

// AuthCodeURL returns the upstream authorization URL for a login attempt,
// using the given state and PKCE verifier (S256).
func (p *Provider) AuthCodeURL(ctx context.Context, redirectURL, state, verifier string) (string, error) {
	prov, err := p.discover(ctx)
	if err != nil {
		return "", err
	}
	conf := p.oauth2Config(prov, redirectURL)
	return conf.AuthCodeURL(state,
		oauth2.S256ChallengeOption(verifier),
		oauth2.SetAuthURLParam("access_type", "online"),
	), nil
}

// VerifyCallback exchanges the code and verifies the returned ID token
// (signature, iss, aud, exp via OIDC discovery). It enforces the provider's
// email allowlists and requires email_verified=true when the provider
// supplies the claim.
func (p *Provider) VerifyCallback(ctx context.Context, redirectURL, code, verifier string) (*Identity, error) {
	prov, err := p.discover(ctx)
	if err != nil {
		return nil, err
	}
	conf := p.oauth2Config(prov, redirectURL)
	tok, err := conf.Exchange(ctx, code, oauth2.VerifierOption(verifier))
	if err != nil {
		return nil, fmt.Errorf("idp %s: code exchange failed: %w", p.cfg.Name, err)
	}
	rawIDToken, ok := tok.Extra("id_token").(string)
	if !ok || rawIDToken == "" {
		return nil, fmt.Errorf("idp %s: no id_token in token response", p.cfg.Name)
	}
	idToken, err := prov.Verifier(&oidc.Config{
		ClientID: p.cfg.ClientID,
		// Default is RS256-only; ES256 is common too (e.g. Apple, some
		// enterprise IdPs).
		SupportedSigningAlgs: []string{oidc.RS256, oidc.ES256},
	}).Verify(ctx, rawIDToken)
	if err != nil {
		return nil, fmt.Errorf("idp %s: id_token verification failed: %w", p.cfg.Name, err)
	}
	var claims struct {
		Email         string `json:"email"`
		EmailVerified *bool  `json:"email_verified"`
	}
	if err := idToken.Claims(&claims); err != nil {
		return nil, fmt.Errorf("idp %s: malformed id_token claims: %w", p.cfg.Name, err)
	}
	if claims.EmailVerified != nil && !*claims.EmailVerified {
		return nil, fmt.Errorf("%w: idp %s: email %q is not verified", ErrDenied, p.cfg.Name, claims.Email)
	}
	if !p.EmailAllowed(claims.Email) {
		return nil, fmt.Errorf("%w: idp %s: email %q is not on the allowlist", ErrDenied, p.cfg.Name, claims.Email)
	}
	return &Identity{
		Subject: p.cfg.Name + ":" + idToken.Subject,
		Email:   claims.Email,
	}, nil
}

// EmailAllowed enforces the provider's allowlists. With no allowlists
// configured, any email is allowed.
func (p *Provider) EmailAllowed(email string) bool {
	if len(p.cfg.AllowedEmails) == 0 && len(p.cfg.AllowedDomains) == 0 {
		return true
	}
	if slices.Contains(p.cfg.AllowedEmails, email) {
		return true
	}
	_, domain, ok := strings.Cut(email, "@")
	return ok && slices.Contains(p.cfg.AllowedDomains, domain)
}

// ErrDenied marks allowlist/verification denials that should surface as 403.
var ErrDenied = errors.New("idp: access denied")
