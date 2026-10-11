package store

import "time"

// API is the storage contract used by tunneld's server components. It is
// satisfied by the local SQLite Store and by internal/stored1's Cloudflare
// D1 client; both must produce identical sentinel behavior (ErrNotFound,
// ErrExists, ErrInvalidAgentKey).
//
// Open/Close are deliberately not part of the contract: construction is
// driver-specific (see store.Open and stored1.New), and only cmd/tunneld
// needs Close, which it handles via io.Closer. HashSecret/CheckSecret are
// pure functions, not storage.
type API interface {
	// CreateTenant creates a tenant without an expiry. It returns ErrExists
	// if the slug is taken.
	CreateTenant(slug, displayName string) error
	// CreateTenantExpiry is CreateTenant with an optional expiry (ephemeral
	// quick-tunnel tenants).
	CreateTenantExpiry(slug, displayName string, expiresAt *time.Time) error
	// GetTenant returns the tenant with the given slug, or ErrNotFound.
	GetTenant(slug string) (*Tenant, error)
	// DeleteTenant removes a tenant and everything under it. It reports
	// false when the tenant did not exist.
	DeleteTenant(slug string) (bool, error)
	// DeleteExpiredTenants removes every ephemeral tenant whose expiry has
	// passed and returns the deleted slugs.
	DeleteExpiredTenants(now time.Time) ([]string, error)
	// CountLiveTenants returns the number of non-expired ephemeral tenants.
	CountLiveTenants(now time.Time) (int, error)
	// QuickRateHit records one quick-tunnel creation attempt from ip in the
	// fixed one-hour window containing now and returns the window's count.
	QuickRateHit(ip string, now time.Time) (int, error)

	// CreateService creates a service under a tenant, generating its agent
	// key; the plaintext key is returned once. ErrExists when (tenant, name)
	// is taken; ErrNotFound when the tenant does not exist.
	CreateService(tenantSlug string, svc *Service) (string, error)
	// GetService returns the named service of a tenant, or ErrNotFound.
	GetService(tenantSlug, name string) (*Service, error)
	// ValidatePassword checks the OAuth authorize password for a service;
	// true when the service has no password or the password matches.
	ValidatePassword(tenantSlug, name, password string) (bool, error)
	// ValidateAgentKey returns the service when key matches its stored agent
	// key hash, ErrNotFound when the service does not exist, and
	// ErrInvalidAgentKey when the key is wrong.
	ValidateAgentKey(tenantSlug, name, key string) (*Service, error)

	// CreateSigningKey stores a PEM-encoded EC private key for the tenant;
	// a no-op when the tenant already has one.
	CreateSigningKey(tenantSlug, privateKeyPEM string) error
	// GetSigningKey returns the PEM-encoded EC private key for the tenant,
	// or ErrNotFound.
	GetSigningKey(tenantSlug string) (string, error)

	// CreateOAuthClient registers a DCR client under the tenant;
	// redirectURIs is a JSON array of strings. ErrExists on re-registration.
	CreateOAuthClient(tenantSlug, clientID, redirectURIs string) error
	// GetOAuthClient returns the redirect URIs JSON for a registered
	// client, or ErrNotFound.
	GetOAuthClient(tenantSlug, clientID string) (redirectURIs string, err error)

	// CreateAuthCode stores a one-time authorization code; codeHash is the
	// SHA-256 hex digest of the code.
	CreateAuthCode(codeHash, tenantSlug, clientID, redirectURI, codeChallenge string, expiresAt time.Time) error
	// ConsumeAuthCode atomically marks the code used and returns it.
	// ErrNotFound when the code does not exist, is expired, or was already
	// used.
	ConsumeAuthCode(codeHash string, now time.Time) (tenantSlug, clientID, redirectURI, codeChallenge string, err error)
}
