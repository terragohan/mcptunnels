// Package store persists tunneld state in SQLite (modernc.org/sqlite, pure
// Go — no cgo).
//
// v2 is multi-tenant: every tenant-scoped table carries a tenant_slug column
// and every tenant-scoped method takes the tenant slug as its first argument.
package store

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"
	_ "modernc.org/sqlite" // registers the "sqlite" database/sql driver
)

// ErrNotFound is returned by Get* methods when the row does not exist.
var ErrNotFound = errors.New("store: not found")

// ErrInvalidToken is returned by ValidateToken when the token is unknown,
// revoked, or malformed.
var ErrInvalidToken = errors.New("store: invalid token")

// ErrInvalidAgentKey is returned by ValidateAgentKey when the key does not
// match the service's stored hash.
var ErrInvalidAgentKey = errors.New("store: invalid agent key")

// ErrExists is returned by Create* methods when the row already exists.
var ErrExists = errors.New("store: already exists")

// DefaultTenantSlug is the built-in tenant used by the legacy (v1) public
// OAuth endpoints until M2 makes them per-tenant. Open ensures it exists.
const DefaultTenantSlug = "default"

// Tenant is a multi-tenant customer, identified by its permanent slug.
type Tenant struct {
	Slug        string
	DisplayName string
	CreatedAt   time.Time
	DisabledAt  *time.Time
}

// Service is a backend service registered under a tenant.
type Service struct {
	Name           string
	AgentKeyHash   string
	IdentitySecret string
	AuthMode       string
	CreatedAt      time.Time
}

// IDPConfig is a per-tenant upstream OIDC identity provider.
type IDPConfig struct {
	Name           string
	ClientID       string
	ClientSecret   string
	Issuer         string
	AllowedEmails  []string
	AllowedDomains []string
	CreatedAt      time.Time
}

// Client is a dynamically registered OAuth client (RFC 7591).
type Client struct {
	ClientID     string
	ClientName   string
	RedirectURIs []string
	GrantTypes   []string
	CreatedAt    time.Time
}

// AuthCode is a one-time authorization code.
type AuthCode struct {
	Code          string
	ClientID      string
	RedirectURI   string
	CodeChallenge string
	Scope         string
	Resource      string
	Subject       string
	Email         string
	ExpiresAt     time.Time
	UsedAt        *time.Time
}

// RefreshToken is an opaque refresh token; only its SHA-256 hash is stored.
type RefreshToken struct {
	TokenHash string
	ClientID  string
	Subject   string
	Email     string
	Scope     string
	Resource  string
	ExpiresAt time.Time
	RevokedAt *time.Time
	RotatedTo *string // hash of the token this one was rotated into
}

// Store wraps the SQLite database. It is safe for concurrent use.
type Store struct {
	db *sql.DB
}

const schema = `
PRAGMA foreign_keys = ON;
CREATE TABLE IF NOT EXISTS tenants (
	slug         TEXT PRIMARY KEY,
	display_name TEXT NOT NULL DEFAULT '',
	created_at   INTEGER NOT NULL,
	disabled_at  INTEGER,
	login_password_hash TEXT NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS tenant_tokens (
	token_id     TEXT PRIMARY KEY,
	token_hash   TEXT NOT NULL,
	tenant_slug  TEXT NOT NULL REFERENCES tenants(slug) ON DELETE CASCADE,
	created_at   INTEGER NOT NULL,
	revoked_at   INTEGER
);
CREATE TABLE IF NOT EXISTS operator_tokens (
	token_id     TEXT PRIMARY KEY,
	token_hash   TEXT NOT NULL,
	created_at   INTEGER NOT NULL,
	revoked_at   INTEGER
);
CREATE TABLE IF NOT EXISTS setup_tokens (
	token_hash   TEXT PRIMARY KEY,
	created_at   INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS invites (
	token_hash   TEXT PRIMARY KEY,
	created_at   INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS services (
	tenant_slug     TEXT NOT NULL REFERENCES tenants(slug) ON DELETE CASCADE,
	name            TEXT NOT NULL,
	agent_key_hash  TEXT NOT NULL,
	identity_secret TEXT NOT NULL DEFAULT '',
	auth_mode       TEXT NOT NULL DEFAULT 'strict',
	created_at      INTEGER NOT NULL,
	PRIMARY KEY (tenant_slug, name)
);
CREATE TABLE IF NOT EXISTS idp_configs (
	tenant_slug     TEXT NOT NULL REFERENCES tenants(slug) ON DELETE CASCADE,
	name            TEXT NOT NULL,
	client_id       TEXT NOT NULL DEFAULT '',
	client_secret   TEXT NOT NULL DEFAULT '',
	issuer          TEXT NOT NULL DEFAULT '',
	allowed_emails  TEXT NOT NULL DEFAULT '[]',
	allowed_domains TEXT NOT NULL DEFAULT '[]',
	created_at      INTEGER NOT NULL,
	PRIMARY KEY (tenant_slug, name)
);
CREATE TABLE IF NOT EXISTS oauth_clients (
	tenant_slug   TEXT NOT NULL REFERENCES tenants(slug) ON DELETE CASCADE,
	client_id     TEXT NOT NULL,
	client_name   TEXT NOT NULL DEFAULT '',
	redirect_uris TEXT NOT NULL,
	grant_types   TEXT NOT NULL,
	created_at    INTEGER NOT NULL,
	PRIMARY KEY (tenant_slug, client_id)
);
CREATE TABLE IF NOT EXISTS auth_codes (
	tenant_slug    TEXT NOT NULL REFERENCES tenants(slug) ON DELETE CASCADE,
	code           TEXT NOT NULL,
	client_id      TEXT NOT NULL,
	redirect_uri   TEXT NOT NULL,
	code_challenge TEXT NOT NULL,
	scope          TEXT NOT NULL DEFAULT '',
	resource       TEXT NOT NULL DEFAULT '',
	subject        TEXT NOT NULL,
	email          TEXT NOT NULL DEFAULT '',
	expires_at     INTEGER NOT NULL,
	used_at        INTEGER,
	PRIMARY KEY (tenant_slug, code)
);
CREATE TABLE IF NOT EXISTS refresh_tokens (
	tenant_slug TEXT NOT NULL REFERENCES tenants(slug) ON DELETE CASCADE,
	token_hash  TEXT NOT NULL,
	client_id   TEXT NOT NULL,
	subject     TEXT NOT NULL,
	email       TEXT NOT NULL DEFAULT '',
	scope       TEXT NOT NULL DEFAULT '',
	resource    TEXT NOT NULL DEFAULT '',
	expires_at  INTEGER NOT NULL,
	revoked_at  INTEGER,
	rotated_to  TEXT,
	PRIMARY KEY (tenant_slug, token_hash)
);
CREATE TABLE IF NOT EXISTS signing_keys (
	tenant_slug TEXT NOT NULL REFERENCES tenants(slug) ON DELETE CASCADE,
	kid         TEXT NOT NULL,
	private_key TEXT NOT NULL,
	created_at  INTEGER NOT NULL,
	PRIMARY KEY (tenant_slug, kid)
);
CREATE TABLE IF NOT EXISTS auth_requests (
	tenant_slug TEXT NOT NULL REFERENCES tenants(slug) ON DELETE CASCADE,
	state       TEXT NOT NULL,
	kind        TEXT NOT NULL,
	payload     TEXT NOT NULL,
	expires_at  INTEGER NOT NULL,
	PRIMARY KEY (tenant_slug, state)
);
CREATE TABLE IF NOT EXISTS audit_log (
	id          INTEGER PRIMARY KEY AUTOINCREMENT,
	tenant_slug TEXT NOT NULL REFERENCES tenants(slug) ON DELETE CASCADE,
	ts          INTEGER NOT NULL,
	event       TEXT NOT NULL,
	subject     TEXT NOT NULL DEFAULT '',
	client_id   TEXT NOT NULL DEFAULT '',
	service     TEXT NOT NULL DEFAULT '',
	ip          TEXT NOT NULL DEFAULT '',
	detail      TEXT NOT NULL DEFAULT '{}'
);
`

// Open opens (creating if needed) the SQLite database at path and applies the
// schema. Foreign keys (ON DELETE CASCADE) and WAL are enabled via connection
// pragmas. It also ensures the built-in default tenant exists, which backs
// the legacy v1 surface until M2.
func Open(path string) (*Store, error) {
	if path == "" {
		return nil, errors.New("store: database path is required")
	}
	if path != ":memory:" {
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			return nil, fmt.Errorf("create db dir: %w", err)
		}
	}
	dsn := fmt.Sprintf("file:%s?_pragma=busy_timeout(5000)&_pragma=foreign_keys(1)&_pragma=journal_mode(WAL)", path)
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("open db: %w", err)
	}
	if err := db.Ping(); err != nil {
		db.Close()
		return nil, fmt.Errorf("connect db: %w", err)
	}
	if _, err := db.Exec(schema); err != nil {
		db.Close()
		return nil, fmt.Errorf("migrate: %w", err)
	}
	// Column-added-later migrations for existing databases; ignore
	// "duplicate column name" on fresh ones.
	if _, err := db.Exec(`ALTER TABLE tenants ADD COLUMN login_password_hash TEXT NOT NULL DEFAULT ''`); err != nil && !isDuplicateColumn(err) {
		db.Close()
		return nil, fmt.Errorf("migrate tenants: %w", err)
	}
	s := &Store{db: db}
	if err := s.EnsureTenant(DefaultTenantSlug, "Default tenant"); err != nil {
		db.Close()
		return nil, fmt.Errorf("ensure default tenant: %w", err)
	}
	return s, nil
}

// Close closes the database.
func (s *Store) Close() error { return s.db.Close() }

func isUniqueViolation(err error) bool {
	return err != nil && strings.Contains(err.Error(), "UNIQUE constraint failed")
}

func isDuplicateColumn(err error) bool {
	return err != nil && strings.Contains(err.Error(), "duplicate column name")
}

// --- Tenants ---

// CreateTenant creates a tenant. It returns ErrExists if the slug is taken.
// Slugs are permanent; renaming is not supported.
func (s *Store) CreateTenant(slug, displayName string) error {
	_, err := s.db.Exec(
		`INSERT INTO tenants (slug, display_name, created_at) VALUES (?, ?, ?)`,
		slug, displayName, time.Now().Unix())
	if isUniqueViolation(err) {
		return ErrExists
	}
	return err
}

// EnsureTenant creates the tenant if it does not exist yet.
func (s *Store) EnsureTenant(slug, displayName string) error {
	err := s.CreateTenant(slug, displayName)
	if errors.Is(err, ErrExists) {
		return nil
	}
	return err
}

// GetTenant returns the tenant with the given slug, or ErrNotFound.
func (s *Store) GetTenant(slug string) (*Tenant, error) {
	var t Tenant
	var createdAt int64
	var disabledAt sql.NullInt64
	err := s.db.QueryRow(
		`SELECT slug, display_name, created_at, disabled_at FROM tenants WHERE slug = ?`, slug).
		Scan(&t.Slug, &t.DisplayName, &createdAt, &disabledAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	t.CreatedAt = time.Unix(createdAt, 0)
	if disabledAt.Valid {
		v := time.Unix(disabledAt.Int64, 0)
		t.DisabledAt = &v
	}
	return &t, nil
}

// ListTenants returns all tenants, ordered by slug.
func (s *Store) ListTenants() ([]Tenant, error) {
	rows, err := s.db.Query(`SELECT slug, display_name, created_at, disabled_at FROM tenants ORDER BY slug`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Tenant
	for rows.Next() {
		var t Tenant
		var createdAt int64
		var disabledAt sql.NullInt64
		if err := rows.Scan(&t.Slug, &t.DisplayName, &createdAt, &disabledAt); err != nil {
			return nil, err
		}
		t.CreatedAt = time.Unix(createdAt, 0)
		if disabledAt.Valid {
			v := time.Unix(disabledAt.Int64, 0)
			t.DisabledAt = &v
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

// DisableTenant marks the tenant disabled. Disabled tenants keep their data
// but the resolver refuses to serve their public endpoints (404).
func (s *Store) DisableTenant(slug string) error {
	res, err := s.db.Exec(`UPDATE tenants SET disabled_at = ? WHERE slug = ? AND disabled_at IS NULL`,
		time.Now().Unix(), slug)
	if err != nil {
		return err
	}
	return s.setDisabledResult(slug, res)
}

// EnableTenant clears the disabled mark.
func (s *Store) EnableTenant(slug string) error {
	res, err := s.db.Exec(`UPDATE tenants SET disabled_at = NULL WHERE slug = ? AND disabled_at IS NOT NULL`, slug)
	if err != nil {
		return err
	}
	return s.setDisabledResult(slug, res)
}

// setDisabledResult maps "no row changed" to ErrNotFound (unknown tenant, or
// already in the target state — callers should check GetTenant first if they
// need to distinguish).
func (s *Store) setDisabledResult(slug string, res sql.Result) error {
	if n, _ := res.RowsAffected(); n == 1 {
		return nil
	}
	if _, err := s.GetTenant(slug); err != nil {
		return err
	}
	return nil // already in the target state
}

// DeleteTenant removes a tenant and, via ON DELETE CASCADE, all of its
// tokens, services, IdP configs and OAuth state. It reports false when the
// tenant did not exist.
func (s *Store) DeleteTenant(slug string) (bool, error) {
	res, err := s.db.Exec(`DELETE FROM tenants WHERE slug = ?`, slug)
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	return n == 1, err
}

// NewLoginPassword generates a per-tenant login password (shown once at
// signup or reset; only the bcrypt hash is stored).
func NewLoginPassword() string {
	return "mcp_pass_" + hex.EncodeToString(randomBytes(12))
}

// SetTenantLoginPassword sets the tenant's OAuth dev-login password,
// replacing any previous one. Only the bcrypt hash is stored.
func (s *Store) SetTenantLoginPassword(slug, plaintext string) error {
	hash, err := HashSecret(plaintext)
	if err != nil {
		return err
	}
	res, err := s.db.Exec(`UPDATE tenants SET login_password_hash = ? WHERE slug = ?`, hash, slug)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// VerifyTenantLogin reports whether password matches the tenant's stored
// login password, and whether the tenant has one at all. When the tenant has
// no password (created before passwords existed), callers fall back to the
// global dev_auth password.
func (s *Store) VerifyTenantLogin(slug, password string) (ok, hasPassword bool, err error) {
	var hash string
	err = s.db.QueryRow(`SELECT login_password_hash FROM tenants WHERE slug = ?`, slug).Scan(&hash)
	if errors.Is(err, sql.ErrNoRows) {
		return false, false, ErrNotFound
	}
	if err != nil {
		return false, false, err
	}
	if hash == "" {
		return false, false, nil
	}
	return CheckSecret(hash, password), true, nil
}

// --- CLI tokens (tenant admin + operator) ---

// Tokens are formatted as "<prefix>_<id>_<secret>" where id is a short random
// lookup key (stored plaintext, primary key) and the full token is stored as a
// bcrypt hash. bcrypt is deliberately slow and not indexable, hence the id.
const (
	tenantTokenPrefix   = "tun_ten"
	operatorTokenPrefix = "tun_op"
	setupTokenPrefix    = "tun_setup"
	agentKeyPrefix      = "tun_agent"
)

// newToken builds a token of the form <prefix>_<id>_<secret>; id is a short
// random lookup key stored plaintext. Both parts are hex so the underscore
// separators are unambiguous (base64url can contain "_").
func newToken(prefix string) (token, id string) {
	id = hex.EncodeToString(randomBytes(6))
	return prefix + "_" + id + "_" + hex.EncodeToString(randomBytes(24)), id
}

// HashSecret bcrypt-hashes a plaintext secret (CLI token, agent key).
func HashSecret(plaintext string) (string, error) {
	h, err := bcrypt.GenerateFromPassword([]byte(plaintext), bcrypt.DefaultCost)
	return string(h), err
}

// CheckSecret reports whether plaintext matches the bcrypt hash.
func CheckSecret(hash, plaintext string) bool {
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(plaintext)) == nil
}

func splitToken(token string) (prefix, id string, ok bool) {
	parts := strings.Split(token, "_")
	// prefixes contain an underscore themselves (tun_ten, tun_op)
	if len(parts) != 4 || parts[0] != "tun" || parts[3] == "" {
		return "", "", false
	}
	prefix = parts[0] + "_" + parts[1]
	if prefix != tenantTokenPrefix && prefix != operatorTokenPrefix {
		return "", "", false
	}
	return prefix, parts[2], true
}

// CreateTenantToken creates a new admin token for the tenant and returns the
// plaintext token. The plaintext is shown once by the CLI and is never
// recoverable — only the bcrypt hash is stored. The tenant must exist.
func (s *Store) CreateTenantToken(tenantSlug string) (string, error) {
	if _, err := s.GetTenant(tenantSlug); err != nil {
		return "", err
	}
	return s.insertToken("tenant_tokens", tenantSlug, tenantTokenPrefix)
}

// RotateTenantToken revokes all existing tokens of the tenant and creates a
// new one, returning the plaintext.
func (s *Store) RotateTenantToken(tenantSlug string) (string, error) {
	if _, err := s.GetTenant(tenantSlug); err != nil {
		return "", err
	}
	tx, err := s.db.Begin()
	if err != nil {
		return "", err
	}
	defer tx.Rollback()
	if _, err := tx.Exec(
		`UPDATE tenant_tokens SET revoked_at = ? WHERE tenant_slug = ? AND revoked_at IS NULL`,
		time.Now().Unix(), tenantSlug); err != nil {
		return "", err
	}
	token, id := newToken(tenantTokenPrefix)
	hash, err := HashSecret(token)
	if err != nil {
		return "", err
	}
	if _, err := tx.Exec(
		`INSERT INTO tenant_tokens (token_id, token_hash, tenant_slug, created_at) VALUES (?, ?, ?, ?)`,
		id, hash, tenantSlug, time.Now().Unix()); err != nil {
		return "", err
	}
	if err := tx.Commit(); err != nil {
		return "", err
	}
	return token, nil
}

func (s *Store) insertToken(table, tenantSlug, prefix string) (string, error) {
	token, id := newToken(prefix)
	hash, err := HashSecret(token)
	if err != nil {
		return "", err
	}
	var q string
	var args []any
	if table == "tenant_tokens" {
		q = `INSERT INTO tenant_tokens (token_id, token_hash, tenant_slug, created_at) VALUES (?, ?, ?, ?)`
		args = []any{id, hash, tenantSlug, time.Now().Unix()}
	} else {
		q = `INSERT INTO operator_tokens (token_id, token_hash, created_at) VALUES (?, ?, ?)`
		args = []any{id, hash, time.Now().Unix()}
	}
	if _, err := s.db.Exec(q, args...); err != nil {
		return "", err
	}
	return token, nil
}

// CreateOperatorToken creates a new operator token, returning the plaintext.
func (s *Store) CreateOperatorToken() (string, error) {
	return s.insertToken("operator_tokens", "", operatorTokenPrefix)
}

// HasOperatorTokens reports whether any active operator token exists.
func (s *Store) HasOperatorTokens() (bool, error) {
	var n int
	err := s.db.QueryRow(`SELECT count(*) FROM operator_tokens WHERE revoked_at IS NULL`).Scan(&n)
	return n > 0, err
}

// ValidateToken resolves a CLI bearer token. For a tenant token it returns
// the tenant slug and isOperator=false; for an operator token it returns an
// empty slug and isOperator=true. Unknown, malformed or revoked tokens yield
// ErrInvalidToken.
func (s *Store) ValidateToken(token string) (tenantSlug string, isOperator bool, err error) {
	prefix, id, ok := splitToken(token)
	if !ok {
		return "", false, ErrInvalidToken
	}
	var hash string
	switch prefix {
	case tenantTokenPrefix:
		err = s.db.QueryRow(
			`SELECT token_hash, tenant_slug FROM tenant_tokens WHERE token_id = ? AND revoked_at IS NULL`, id).
			Scan(&hash, &tenantSlug)
	case operatorTokenPrefix:
		err = s.db.QueryRow(
			`SELECT token_hash FROM operator_tokens WHERE token_id = ? AND revoked_at IS NULL`, id).
			Scan(&hash)
		isOperator = true
	}
	if errors.Is(err, sql.ErrNoRows) {
		return "", false, ErrInvalidToken
	}
	if err != nil {
		return "", false, err
	}
	if !CheckSecret(hash, token) {
		return "", false, ErrInvalidToken
	}
	return tenantSlug, isOperator, nil
}

// RevokeTenantTokens revokes all active tokens of a tenant. Used by tests and
// administrative flows.
func (s *Store) RevokeTenantTokens(tenantSlug string, at time.Time) error {
	_, err := s.db.Exec(
		`UPDATE tenant_tokens SET revoked_at = ? WHERE tenant_slug = ? AND revoked_at IS NULL`,
		at.Unix(), tenantSlug)
	return err
}

// --- Setup tokens (one-time bootstrap) ---

// CreateSetupToken creates a one-time setup token (printed by tunneld on
// first run) and returns the plaintext. Only the bcrypt hash is stored.
// Setup tokens are few (typically one), so ConsumeSetupToken scans them.
func (s *Store) CreateSetupToken() (string, error) {
	token := setupTokenPrefix + "_" + hex.EncodeToString(randomBytes(24))
	hash, err := HashSecret(token)
	if err != nil {
		return "", err
	}
	if _, err := s.db.Exec(
		`INSERT INTO setup_tokens (token_hash, created_at) VALUES (?, ?)`,
		hash, time.Now().Unix()); err != nil {
		return "", err
	}
	return token, nil
}

// ConsumeSetupToken validates a setup token and deletes it, so it can only be
// used once. It reports false when the token is unknown.
func (s *Store) ConsumeSetupToken(token string) (bool, error) {
	if !strings.HasPrefix(token, setupTokenPrefix+"_") {
		return false, nil
	}
	rows, err := s.db.Query(`SELECT token_hash FROM setup_tokens`)
	if err != nil {
		return false, err
	}
	defer rows.Close()
	var hashes []string
	for rows.Next() {
		var h string
		if err := rows.Scan(&h); err != nil {
			return false, err
		}
		hashes = append(hashes, h)
	}
	if err := rows.Err(); err != nil {
		return false, err
	}
	for _, h := range hashes {
		if CheckSecret(h, token) {
			if _, err := s.db.Exec(`DELETE FROM setup_tokens WHERE token_hash = ?`, h); err != nil {
				return false, err
			}
			return true, nil
		}
	}
	return false, nil
}

// --- Invites (signup gating) ---

// Invite codes gate public signup: an operator creates them
// (`mcptunnel admin invite create`) and hands them out; a signup consumes one.
// They use the same scan-and-delete scheme as setup tokens — both tables are
// expected to stay tiny.
const invitePrefix = "mcp_invite"

// CreateInvite creates a one-time invite code and returns the plaintext. Only
// the bcrypt hash is stored.
func (s *Store) CreateInvite() (string, error) {
	code := invitePrefix + "_" + hex.EncodeToString(randomBytes(24))
	hash, err := HashSecret(code)
	if err != nil {
		return "", err
	}
	if _, err := s.db.Exec(
		`INSERT INTO invites (token_hash, created_at) VALUES (?, ?)`,
		hash, time.Now().Unix()); err != nil {
		return "", err
	}
	return code, nil
}

// ConsumeInvite validates an invite code and deletes it, so it can only be
// used once. It reports false when the code is unknown.
func (s *Store) ConsumeInvite(code string) (bool, error) {
	if !strings.HasPrefix(code, invitePrefix+"_") {
		return false, nil
	}
	rows, err := s.db.Query(`SELECT token_hash FROM invites`)
	if err != nil {
		return false, err
	}
	defer rows.Close()
	var hashes []string
	for rows.Next() {
		var h string
		if err := rows.Scan(&h); err != nil {
			return false, err
		}
		hashes = append(hashes, h)
	}
	if err := rows.Err(); err != nil {
		return false, err
	}
	for _, h := range hashes {
		if CheckSecret(h, code) {
			if _, err := s.db.Exec(`DELETE FROM invites WHERE token_hash = ?`, h); err != nil {
				return false, err
			}
			return true, nil
		}
	}
	return false, nil
}

func randomBytes(n int) []byte {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return b
}

// --- Services ---

// newAgentKey generates a plaintext agent key and its bcrypt hash.
func newAgentKey() (plaintext, hash string, err error) {
	plaintext = agentKeyPrefix + "_" + hex.EncodeToString(randomBytes(24))
	hash, err = HashSecret(plaintext)
	if err != nil {
		return "", "", err
	}
	return plaintext, hash, nil
}

// CreateService creates a service under a tenant, generating its agent key
// (`tun_agent_<hex>`); the plaintext key is returned once and only its bcrypt
// hash is stored. ErrExists is returned when (tenant_slug, name) is taken;
// ErrNotFound when the tenant does not exist.
func (s *Store) CreateService(tenantSlug string, svc *Service) (string, error) {
	if _, err := s.GetTenant(tenantSlug); err != nil {
		return "", err
	}
	if svc.AuthMode == "" {
		svc.AuthMode = "strict"
	}
	plaintext, hash, err := newAgentKey()
	if err != nil {
		return "", err
	}
	svc.AgentKeyHash = hash
	svc.CreatedAt = time.Now()
	_, err = s.db.Exec(
		`INSERT INTO services (tenant_slug, name, agent_key_hash, identity_secret, auth_mode, created_at)
		 VALUES (?, ?, ?, ?, ?, ?)`,
		tenantSlug, svc.Name, svc.AgentKeyHash, svc.IdentitySecret, svc.AuthMode, svc.CreatedAt.Unix())
	if isUniqueViolation(err) {
		return "", ErrExists
	}
	if err != nil {
		return "", err
	}
	return plaintext, nil
}

// GetService returns the named service of a tenant, or ErrNotFound.
func (s *Store) GetService(tenantSlug, name string) (*Service, error) {
	var svc Service
	var createdAt int64
	err := s.db.QueryRow(
		`SELECT name, agent_key_hash, identity_secret, auth_mode, created_at
		 FROM services WHERE tenant_slug = ? AND name = ?`, tenantSlug, name).
		Scan(&svc.Name, &svc.AgentKeyHash, &svc.IdentitySecret, &svc.AuthMode, &createdAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	svc.CreatedAt = time.Unix(createdAt, 0)
	return &svc, nil
}

// ListServices returns all services of a tenant, ordered by name.
func (s *Store) ListServices(tenantSlug string) ([]Service, error) {
	rows, err := s.db.Query(
		`SELECT name, agent_key_hash, identity_secret, auth_mode, created_at
		 FROM services WHERE tenant_slug = ? ORDER BY name`, tenantSlug)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Service
	for rows.Next() {
		var svc Service
		var createdAt int64
		if err := rows.Scan(&svc.Name, &svc.AgentKeyHash, &svc.IdentitySecret, &svc.AuthMode, &createdAt); err != nil {
			return nil, err
		}
		svc.CreatedAt = time.Unix(createdAt, 0)
		out = append(out, svc)
	}
	return out, rows.Err()
}

// DeleteService removes a service. It reports false when it did not exist.
func (s *Store) DeleteService(tenantSlug, name string) (bool, error) {
	res, err := s.db.Exec(`DELETE FROM services WHERE tenant_slug = ? AND name = ?`, tenantSlug, name)
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	return n == 1, err
}

// RotateAgentKey replaces the agent key of a service with a freshly generated
// one and returns the plaintext. The old key stops working immediately. It
// returns ErrNotFound when the service does not exist.
func (s *Store) RotateAgentKey(tenantSlug, name string) (string, error) {
	plaintext, hash, err := newAgentKey()
	if err != nil {
		return "", err
	}
	res, err := s.db.Exec(
		`UPDATE services SET agent_key_hash = ? WHERE tenant_slug = ? AND name = ?`,
		hash, tenantSlug, name)
	if err != nil {
		return "", err
	}
	if n, _ := res.RowsAffected(); n != 1 {
		return "", ErrNotFound
	}
	return plaintext, nil
}

// ValidateAgentKey returns the service when key matches its stored agent key
// hash, ErrNotFound when the service does not exist, and ErrInvalidAgentKey
// when the key is wrong.
func (s *Store) ValidateAgentKey(tenantSlug, name, key string) (*Service, error) {
	svc, err := s.GetService(tenantSlug, name)
	if err != nil {
		return nil, err
	}
	if key == "" || !CheckSecret(svc.AgentKeyHash, key) {
		return nil, ErrInvalidAgentKey
	}
	return svc, nil
}

// --- IdP configs ---

// SetIDP creates or replaces a tenant's IdP config by name (upsert).
func (s *Store) SetIDP(tenantSlug string, c *IDPConfig) error {
	if _, err := s.GetTenant(tenantSlug); err != nil {
		return err
	}
	emails, err := json.Marshal(c.AllowedEmails)
	if err != nil {
		return err
	}
	domains, err := json.Marshal(c.AllowedDomains)
	if err != nil {
		return err
	}
	_, err = s.db.Exec(
		`INSERT INTO idp_configs (tenant_slug, name, client_id, client_secret, issuer, allowed_emails, allowed_domains, created_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?)
		 ON CONFLICT (tenant_slug, name) DO UPDATE SET
		   client_id = excluded.client_id,
		   client_secret = excluded.client_secret,
		   issuer = excluded.issuer,
		   allowed_emails = excluded.allowed_emails,
		   allowed_domains = excluded.allowed_domains`,
		tenantSlug, c.Name, c.ClientID, c.ClientSecret, c.Issuer, emails, domains, time.Now().Unix())
	return err
}

// ListIDP returns the tenant's IdP configs, ordered by name.
func (s *Store) ListIDP(tenantSlug string) ([]IDPConfig, error) {
	rows, err := s.db.Query(
		`SELECT name, client_id, client_secret, issuer, allowed_emails, allowed_domains, created_at
		 FROM idp_configs WHERE tenant_slug = ? ORDER BY name`, tenantSlug)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []IDPConfig
	for rows.Next() {
		var c IDPConfig
		var emails, domains string
		var createdAt int64
		if err := rows.Scan(&c.Name, &c.ClientID, &c.ClientSecret, &c.Issuer, &emails, &domains, &createdAt); err != nil {
			return nil, err
		}
		if err := json.Unmarshal([]byte(emails), &c.AllowedEmails); err != nil {
			return nil, err
		}
		if err := json.Unmarshal([]byte(domains), &c.AllowedDomains); err != nil {
			return nil, err
		}
		c.CreatedAt = time.Unix(createdAt, 0)
		out = append(out, c)
	}
	return out, rows.Err()
}

// DeleteIDP removes a tenant's IdP config. It reports false when the config
// did not exist.
func (s *Store) DeleteIDP(tenantSlug, name string) (bool, error) {
	res, err := s.db.Exec(`DELETE FROM idp_configs WHERE tenant_slug = ? AND name = ?`, tenantSlug, name)
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	return n == 1, err
}

// --- OAuth clients ---

// InsertClient stores a newly registered client.
func (s *Store) InsertClient(tenantSlug string, c *Client) error {
	uris, err := json.Marshal(c.RedirectURIs)
	if err != nil {
		return err
	}
	grants, err := json.Marshal(c.GrantTypes)
	if err != nil {
		return err
	}
	_, err = s.db.Exec(
		`INSERT INTO oauth_clients (tenant_slug, client_id, client_name, redirect_uris, grant_types, created_at)
		 VALUES (?, ?, ?, ?, ?, ?)`,
		tenantSlug, c.ClientID, c.ClientName, uris, grants, c.CreatedAt.Unix())
	return err
}

// GetClient returns the client with the given ID, or ErrNotFound.
func (s *Store) GetClient(tenantSlug, clientID string) (*Client, error) {
	var c Client
	var uris, grants string
	var createdAt int64
	err := s.db.QueryRow(
		`SELECT client_id, client_name, redirect_uris, grant_types, created_at
		 FROM oauth_clients WHERE tenant_slug = ? AND client_id = ?`, tenantSlug, clientID).
		Scan(&c.ClientID, &c.ClientName, &uris, &grants, &createdAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal([]byte(uris), &c.RedirectURIs); err != nil {
		return nil, err
	}
	if err := json.Unmarshal([]byte(grants), &c.GrantTypes); err != nil {
		return nil, err
	}
	c.CreatedAt = time.Unix(createdAt, 0)
	return &c, nil
}

// ListClients returns all registered OAuth clients of a tenant, oldest first.
func (s *Store) ListClients(tenantSlug string) ([]Client, error) {
	rows, err := s.db.Query(
		`SELECT client_id, client_name, redirect_uris, grant_types, created_at
		 FROM oauth_clients WHERE tenant_slug = ? ORDER BY created_at`, tenantSlug)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Client
	for rows.Next() {
		var c Client
		var uris, grants string
		var createdAt int64
		if err := rows.Scan(&c.ClientID, &c.ClientName, &uris, &grants, &createdAt); err != nil {
			return nil, err
		}
		if err := json.Unmarshal([]byte(uris), &c.RedirectURIs); err != nil {
			return nil, err
		}
		if err := json.Unmarshal([]byte(grants), &c.GrantTypes); err != nil {
			return nil, err
		}
		c.CreatedAt = time.Unix(createdAt, 0)
		out = append(out, c)
	}
	return out, rows.Err()
}

// DeleteClient removes a registered client. It reports false when the client
// did not exist.
func (s *Store) DeleteClient(tenantSlug, clientID string) (bool, error) {
	res, err := s.db.Exec(`DELETE FROM oauth_clients WHERE tenant_slug = ? AND client_id = ?`, tenantSlug, clientID)
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	return n == 1, err
}

// RevokeClientTokens revokes every unrevoked refresh token of a client.
// Returns the number of tokens revoked.
func (s *Store) RevokeClientTokens(tenantSlug, clientID string, at time.Time) (int64, error) {
	res, err := s.db.Exec(
		`UPDATE refresh_tokens SET revoked_at = ? WHERE tenant_slug = ? AND client_id = ? AND revoked_at IS NULL`,
		at.Unix(), tenantSlug, clientID)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

// --- Authorization codes ---

// InsertAuthCode stores a new authorization code.
func (s *Store) InsertAuthCode(tenantSlug string, ac *AuthCode) error {
	_, err := s.db.Exec(
		`INSERT INTO auth_codes (tenant_slug, code, client_id, redirect_uri, code_challenge, scope, resource, subject, email, expires_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		tenantSlug, ac.Code, ac.ClientID, ac.RedirectURI, ac.CodeChallenge, ac.Scope, ac.Resource, ac.Subject, ac.Email, ac.ExpiresAt.Unix())
	return err
}

// GetAuthCode returns the code, or ErrNotFound.
func (s *Store) GetAuthCode(tenantSlug, code string) (*AuthCode, error) {
	var ac AuthCode
	var expiresAt int64
	var usedAt sql.NullInt64
	err := s.db.QueryRow(
		`SELECT code, client_id, redirect_uri, code_challenge, scope, resource, subject, email, expires_at, used_at
		 FROM auth_codes WHERE tenant_slug = ? AND code = ?`, tenantSlug, code).
		Scan(&ac.Code, &ac.ClientID, &ac.RedirectURI, &ac.CodeChallenge, &ac.Scope, &ac.Resource, &ac.Subject, &ac.Email, &expiresAt, &usedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	ac.ExpiresAt = time.Unix(expiresAt, 0)
	if usedAt.Valid {
		t := time.Unix(usedAt.Int64, 0)
		ac.UsedAt = &t
	}
	return &ac, nil
}

// MarkAuthCodeUsed atomically marks the code used. It reports false if the
// code was already used (replay protection).
func (s *Store) MarkAuthCodeUsed(tenantSlug, code string, at time.Time) (bool, error) {
	res, err := s.db.Exec(
		`UPDATE auth_codes SET used_at = ? WHERE tenant_slug = ? AND code = ? AND used_at IS NULL`,
		at.Unix(), tenantSlug, code)
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	return n == 1, err
}

// --- Refresh tokens ---

// InsertRefreshToken stores a new refresh token.
func (s *Store) InsertRefreshToken(tenantSlug string, rt *RefreshToken) error {
	_, err := s.db.Exec(
		`INSERT INTO refresh_tokens (tenant_slug, token_hash, client_id, subject, email, scope, resource, expires_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		tenantSlug, rt.TokenHash, rt.ClientID, rt.Subject, rt.Email, rt.Scope, rt.Resource, rt.ExpiresAt.Unix())
	return err
}

// GetRefreshToken returns the token with the given hash, or ErrNotFound.
func (s *Store) GetRefreshToken(tenantSlug, tokenHash string) (*RefreshToken, error) {
	var rt RefreshToken
	var expiresAt int64
	var revokedAt sql.NullInt64
	var rotatedTo sql.NullString
	err := s.db.QueryRow(
		`SELECT token_hash, client_id, subject, email, scope, resource, expires_at, revoked_at, rotated_to
		 FROM refresh_tokens WHERE tenant_slug = ? AND token_hash = ?`, tenantSlug, tokenHash).
		Scan(&rt.TokenHash, &rt.ClientID, &rt.Subject, &rt.Email, &rt.Scope, &rt.Resource, &expiresAt, &revokedAt, &rotatedTo)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	rt.ExpiresAt = time.Unix(expiresAt, 0)
	if revokedAt.Valid {
		t := time.Unix(revokedAt.Int64, 0)
		rt.RevokedAt = &t
	}
	if rotatedTo.Valid {
		rt.RotatedTo = &rotatedTo.String
	}
	return &rt, nil
}

// RotateRefreshToken atomically marks oldHash as rotated into newHash. It
// reports false if the token was already rotated or revoked — i.e. a reuse
// attempt.
func (s *Store) RotateRefreshToken(tenantSlug, oldHash, newHash string, at time.Time) (bool, error) {
	res, err := s.db.Exec(
		`UPDATE refresh_tokens SET rotated_to = ?
		 WHERE tenant_slug = ? AND token_hash = ? AND rotated_to IS NULL AND revoked_at IS NULL`,
		newHash, tenantSlug, oldHash)
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	return n == 1, err
}

// RevokeRefreshChain revokes the token with the given hash and every token it
// was (transitively) rotated into. Used when a rotated token is replayed.
func (s *Store) RevokeRefreshChain(tenantSlug, tokenHash string, at time.Time) error {
	for hash := tokenHash; hash != ""; {
		var next sql.NullString
		res, err := s.db.Exec(
			`UPDATE refresh_tokens SET revoked_at = ?
			 WHERE tenant_slug = ? AND token_hash = ? AND revoked_at IS NULL`,
			at.Unix(), tenantSlug, hash)
		if err != nil {
			return err
		}
		if n, _ := res.RowsAffected(); n == 0 {
			// Already revoked; still need to walk forward.
		}
		err = s.db.QueryRow(
			`SELECT rotated_to FROM refresh_tokens WHERE tenant_slug = ? AND token_hash = ?`,
			tenantSlug, hash).Scan(&next)
		if errors.Is(err, sql.ErrNoRows) {
			return nil
		}
		if err != nil {
			return err
		}
		if !next.Valid {
			return nil
		}
		hash = next.String
	}
	return nil
}

// --- Signing keys ---

// SigningKey returns the newest persisted ES256 signing key of a tenant,
// generating and storing one on first use.
func (s *Store) SigningKey(tenantSlug string) (kid string, key *ecdsa.PrivateKey, err error) {
	var pemData string
	// kid contains a nanosecond timestamp, so ordering by created_at then kid
	// yields the most recently inserted key.
	err = s.db.QueryRow(
		`SELECT kid, private_key FROM signing_keys WHERE tenant_slug = ?
		 ORDER BY created_at DESC, kid DESC LIMIT 1`, tenantSlug).Scan(&kid, &pemData)
	if err == nil {
		block, _ := pem.Decode([]byte(pemData))
		if block == nil {
			return "", nil, errors.New("store: corrupt signing key PEM")
		}
		parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return "", nil, fmt.Errorf("store: parse signing key: %w", err)
		}
		ecKey, ok := parsed.(*ecdsa.PrivateKey)
		if !ok {
			return "", nil, errors.New("store: signing key is not ECDSA")
		}
		return kid, ecKey, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return "", nil, err
	}

	// First use: generate and persist an ES256 key.
	return s.RotateSigningKey(tenantSlug)
}

// RotateSigningKey generates and persists a new ES256 signing key for a
// tenant, making it the active (newest) key. The previous key stays in the
// table, but only the active key's public half is served via JWKS — so
// rotation invalidates outstanding access tokens (short-lived by design). A
// tunneld restart is required to pick the new key up.
func (s *Store) RotateSigningKey(tenantSlug string) (string, *ecdsa.PrivateKey, error) {
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return "", nil, err
	}
	der, err := x509.MarshalPKCS8PrivateKey(ecKey)
	if err != nil {
		return "", nil, err
	}
	pemData := string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
	kid := fmt.Sprintf("key-%d", time.Now().UnixNano())
	if _, err := s.db.Exec(
		`INSERT INTO signing_keys (tenant_slug, kid, private_key, created_at) VALUES (?, ?, ?, ?)`,
		tenantSlug, kid, pemData, time.Now().Unix()); err != nil {
		return "", nil, err
	}
	return kid, ecKey, nil
}

// --- Pending authorization requests (OIDC broker + consent state) ---

// InsertAuthRequest stores a pending authorization request under a random
// state key. payload is an opaque JSON blob owned by the caller.
func (s *Store) InsertAuthRequest(tenantSlug, state, kind string, payload []byte, expiresAt time.Time) error {
	_, err := s.db.Exec(
		`INSERT INTO auth_requests (tenant_slug, state, kind, payload, expires_at) VALUES (?, ?, ?, ?, ?)`,
		tenantSlug, state, kind, payload, expiresAt.Unix())
	return err
}

// ConsumeAuthRequest atomically fetches and deletes the request with the
// given state, so it can only be used once. It returns ErrNotFound when the
// state is unknown, and ErrNotFound as well when the row existed but is
// expired (it is deleted either way).
func (s *Store) ConsumeAuthRequest(tenantSlug, state string) (kind string, payload []byte, err error) {
	tx, err := s.db.Begin()
	if err != nil {
		return "", nil, err
	}
	defer tx.Rollback()
	var expiresAt int64
	err = tx.QueryRow(
		`SELECT kind, payload, expires_at FROM auth_requests WHERE tenant_slug = ? AND state = ?`,
		tenantSlug, state).Scan(&kind, &payload, &expiresAt)
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil, ErrNotFound
	}
	if err != nil {
		return "", nil, err
	}
	if _, err := tx.Exec(`DELETE FROM auth_requests WHERE tenant_slug = ? AND state = ?`, tenantSlug, state); err != nil {
		return "", nil, err
	}
	if err := tx.Commit(); err != nil {
		return "", nil, err
	}
	if time.Now().After(time.Unix(expiresAt, 0)) {
		return "", nil, ErrNotFound
	}
	return kind, payload, nil
}

// --- Audit log ---

// AuditEntry is one row of the append-only audit log.
type AuditEntry struct {
	ID       int64
	TS       time.Time
	Event    string
	Subject  string
	ClientID string
	Service  string
	IP       string
	Detail   string // JSON object
}

// LogAudit appends an entry to the audit log. detail is a JSON object; empty
// becomes "{}".
func (s *Store) LogAudit(tenantSlug string, e AuditEntry) error {
	if e.Detail == "" {
		e.Detail = "{}"
	}
	ts := e.TS
	if ts.IsZero() {
		ts = time.Now()
	}
	_, err := s.db.Exec(
		`INSERT INTO audit_log (tenant_slug, ts, event, subject, client_id, service, ip, detail)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		tenantSlug, ts.Unix(), e.Event, e.Subject, e.ClientID, e.Service, e.IP, e.Detail)
	return err
}

// ListAudit returns the most recent audit entries of a tenant, newest first.
func (s *Store) ListAudit(tenantSlug string, limit int) ([]AuditEntry, error) {
	if limit <= 0 {
		limit = 50
	}
	rows, err := s.db.Query(
		`SELECT id, ts, event, subject, client_id, service, ip, detail
		 FROM audit_log WHERE tenant_slug = ? ORDER BY id DESC LIMIT ?`, tenantSlug, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []AuditEntry
	for rows.Next() {
		var e AuditEntry
		var ts int64
		if err := rows.Scan(&e.ID, &ts, &e.Event, &e.Subject, &e.ClientID, &e.Service, &e.IP, &e.Detail); err != nil {
			return nil, err
		}
		e.TS = time.Unix(ts, 0)
		out = append(out, e)
	}
	return out, rows.Err()
}
