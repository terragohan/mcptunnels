// Package store persists tunneld state in SQLite (modernc.org/sqlite, pure
// Go — no cgo).
//
// tunneld is a quick-tunnel service: the only tenants are ephemeral
// quick-tunnel tenants (random "q-*" slug, expires_at set), each holding a
// single service whose agent key authenticates the outbound agent connection.
package store

import (
	"crypto/rand"
	"database/sql"
	"encoding/hex"
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

// ErrInvalidAgentKey is returned by ValidateAgentKey when the key does not
// match the service's stored hash.
var ErrInvalidAgentKey = errors.New("store: invalid agent key")

// ErrExists is returned by Create* methods when the row already exists.
var ErrExists = errors.New("store: already exists")

// Tenant is an ephemeral quick-tunnel tenant, identified by its random slug.
type Tenant struct {
	Slug        string
	DisplayName string
	CreatedAt   time.Time
	// ExpiresAt marks the tenant ephemeral; the tunneld janitor deletes it
	// once the time passes.
	ExpiresAt *time.Time
}

// Service is the single MCP service exposed under a tenant.
type Service struct {
	Name         string
	AgentKeyHash string
	// AuthMode is "oauth" (bearer-gated) or "open" (no auth). Empty defaults
	// to "oauth" at insert time.
	AuthMode string
	// PasswordHash is the bcrypt hash of the OAuth authorize password. Empty
	// for "open" services (no password).
	PasswordHash string
	CreatedAt    time.Time
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
	expires_at   INTEGER
);
CREATE TABLE IF NOT EXISTS services (
	tenant_slug     TEXT NOT NULL REFERENCES tenants(slug) ON DELETE CASCADE,
	name            TEXT NOT NULL,
	agent_key_hash  TEXT NOT NULL,
	created_at      INTEGER NOT NULL,
	PRIMARY KEY (tenant_slug, name)
);
CREATE TABLE IF NOT EXISTS quick_rate (
	ip           TEXT NOT NULL,
	window_start INTEGER NOT NULL,
	count        INTEGER NOT NULL,
	PRIMARY KEY (ip, window_start)
);
CREATE TABLE IF NOT EXISTS signing_keys (
	tenant_slug     TEXT PRIMARY KEY REFERENCES tenants(slug) ON DELETE CASCADE,
	private_key_pem TEXT NOT NULL,
	created_at      INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS oauth_clients (
	tenant_slug   TEXT NOT NULL REFERENCES tenants(slug) ON DELETE CASCADE,
	client_id     TEXT NOT NULL,
	redirect_uris TEXT NOT NULL DEFAULT '[]',
	created_at    INTEGER NOT NULL,
	PRIMARY KEY (tenant_slug, client_id)
);
CREATE TABLE IF NOT EXISTS auth_codes (
	code_hash      TEXT PRIMARY KEY,
	tenant_slug    TEXT NOT NULL REFERENCES tenants(slug) ON DELETE CASCADE,
	client_id      TEXT NOT NULL,
	redirect_uri   TEXT NOT NULL,
	code_challenge TEXT NOT NULL,
	expires_at     INTEGER NOT NULL,
	used_at        INTEGER
);
`

// Open opens (creating if needed) the SQLite database at path and applies the
// schema. Foreign keys (ON DELETE CASCADE) and WAL are enabled via connection
// pragmas. Databases created by older versions keep their now-unused tables
// and columns (tokens, invites, OAuth state, ...); they are simply never
// touched — no destructive migrations.
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
	// Column-added-later migration for databases created before tenants had
	// expires_at; ignore "duplicate column name" on fresh ones.
	if _, err := db.Exec(`ALTER TABLE tenants ADD COLUMN expires_at INTEGER`); err != nil && !isDuplicateColumn(err) {
		db.Close()
		return nil, fmt.Errorf("migrate tenants: %w", err)
	}
	// Same pattern for services.auth_mode (OAuth on quick tunnels).
	if _, err := db.Exec(`ALTER TABLE services ADD COLUMN auth_mode TEXT NOT NULL DEFAULT 'oauth'`); err != nil && !isDuplicateColumn(err) {
		db.Close()
		return nil, fmt.Errorf("migrate services: %w", err)
	}
	// Same for services.password_hash (authorize password).
	if _, err := db.Exec(`ALTER TABLE services ADD COLUMN password_hash TEXT NOT NULL DEFAULT ''`); err != nil && !isDuplicateColumn(err) {
		db.Close()
		return nil, fmt.Errorf("migrate services password_hash: %w", err)
	}
	return &Store{db: db}, nil
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

// CreateTenant creates a tenant without an expiry. It returns ErrExists if
// the slug is taken. Slugs are permanent; renaming is not supported.
func (s *Store) CreateTenant(slug, displayName string) error {
	return s.CreateTenantExpiry(slug, displayName, nil)
}

// CreateTenantExpiry is CreateTenant with an optional expiry (ephemeral
// quick-tunnel tenants).
func (s *Store) CreateTenantExpiry(slug, displayName string, expiresAt *time.Time) error {
	var exp any
	if expiresAt != nil {
		exp = expiresAt.Unix()
	}
	_, err := s.db.Exec(
		`INSERT INTO tenants (slug, display_name, created_at, expires_at) VALUES (?, ?, ?, ?)`,
		slug, displayName, time.Now().Unix(), exp)
	if isUniqueViolation(err) {
		return ErrExists
	}
	return err
}

// GetTenant returns the tenant with the given slug, or ErrNotFound.
func (s *Store) GetTenant(slug string) (*Tenant, error) {
	var t Tenant
	var createdAt int64
	var expiresAt sql.NullInt64
	err := s.db.QueryRow(
		`SELECT slug, display_name, created_at, expires_at FROM tenants WHERE slug = ?`, slug).
		Scan(&t.Slug, &t.DisplayName, &createdAt, &expiresAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	t.CreatedAt = time.Unix(createdAt, 0)
	if expiresAt.Valid {
		v := time.Unix(expiresAt.Int64, 0)
		t.ExpiresAt = &v
	}
	return &t, nil
}

// DeleteTenant removes a tenant and, via ON DELETE CASCADE, its services. It
// reports false when the tenant did not exist.
func (s *Store) DeleteTenant(slug string) (bool, error) {
	res, err := s.db.Exec(`DELETE FROM tenants WHERE slug = ?`, slug)
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	return n == 1, err
}

// DeleteExpiredTenants removes every ephemeral tenant whose expires_at is at
// or before now (cascading like DeleteTenant) and returns the deleted slugs.
func (s *Store) DeleteExpiredTenants(now time.Time) ([]string, error) {
	rows, err := s.db.Query(
		`SELECT slug FROM tenants WHERE expires_at IS NOT NULL AND expires_at <= ?`, now.Unix())
	if err != nil {
		return nil, err
	}
	var slugs []string
	for rows.Next() {
		var slug string
		if err := rows.Scan(&slug); err != nil {
			rows.Close()
			return nil, err
		}
		slugs = append(slugs, slug)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	for _, slug := range slugs {
		if _, err := s.DeleteTenant(slug); err != nil {
			return slugs, err
		}
	}
	return slugs, nil
}

// CountLiveTenants returns the number of non-expired ephemeral tenants
// (expires_at set and still in the future).
func (s *Store) CountLiveTenants(now time.Time) (int, error) {
	var n int
	err := s.db.QueryRow(
		`SELECT COUNT(*) FROM tenants WHERE expires_at IS NOT NULL AND expires_at > ?`, now.Unix()).
		Scan(&n)
	return n, err
}

// --- Quick-tunnel rate limiting ---

// QuickRateHit records one quick-tunnel creation attempt from ip in the
// fixed one-hour window containing now and returns the window's hit count.
// The counters live in the database, so the limit survives tunneld restarts.
// Windows older than two hours are pruned on the way.
func (s *Store) QuickRateHit(ip string, now time.Time) (int, error) {
	window := now.Unix() / 3600
	if _, err := s.db.Exec(`DELETE FROM quick_rate WHERE window_start < ?`, window-2); err != nil {
		return 0, err
	}
	if _, err := s.db.Exec(
		`INSERT INTO quick_rate (ip, window_start, count) VALUES (?, ?, 1)
		 ON CONFLICT (ip, window_start) DO UPDATE SET count = count + 1`,
		ip, window); err != nil {
		return 0, err
	}
	var count int
	err := s.db.QueryRow(
		`SELECT count FROM quick_rate WHERE ip = ? AND window_start = ?`, ip, window).
		Scan(&count)
	return count, err
}

// HashSecret bcrypt-hashes a plaintext secret (agent key).
func HashSecret(plaintext string) (string, error) {
	h, err := bcrypt.GenerateFromPassword([]byte(plaintext), bcrypt.DefaultCost)
	return string(h), err
}

// CheckSecret reports whether plaintext matches the bcrypt hash.
func CheckSecret(hash, plaintext string) bool {
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(plaintext)) == nil
}

func randomBytes(n int) []byte {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return b
}

// --- Services ---

const agentKeyPrefix = "tun_agent"

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
// ErrNotFound when the tenant does not exist. An empty AuthMode defaults to
// "oauth".
func (s *Store) CreateService(tenantSlug string, svc *Service) (string, error) {
	if _, err := s.GetTenant(tenantSlug); err != nil {
		return "", err
	}
	plaintext, hash, err := newAgentKey()
	if err != nil {
		return "", err
	}
	svc.AgentKeyHash = hash
	svc.CreatedAt = time.Now()
	if svc.AuthMode == "" {
		svc.AuthMode = "oauth"
	}
	_, err = s.db.Exec(
		`INSERT INTO services (tenant_slug, name, agent_key_hash, auth_mode, password_hash, created_at)
		 VALUES (?, ?, ?, ?, ?, ?)`,
		tenantSlug, svc.Name, svc.AgentKeyHash, svc.AuthMode, svc.PasswordHash, svc.CreatedAt.Unix())
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
		`SELECT name, agent_key_hash, auth_mode, password_hash, created_at
		 FROM services WHERE tenant_slug = ? AND name = ?`, tenantSlug, name).
		Scan(&svc.Name, &svc.AgentKeyHash, &svc.AuthMode, &svc.PasswordHash, &createdAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	svc.CreatedAt = time.Unix(createdAt, 0)
	return &svc, nil
}

// ValidatePassword checks the OAuth authorize password for a service. Returns
// true when the service has no password (open) or the password matches.
func (s *Store) ValidatePassword(tenantSlug, name, password string) (bool, error) {
	svc, err := s.GetService(tenantSlug, name)
	if err != nil {
		return false, err
	}
	if svc.PasswordHash == "" {
		return true, nil // no password set
	}
	return CheckSecret(svc.PasswordHash, password), nil
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

// --- OAuth ---

// CreateSigningKey stores a PEM-encoded EC private key for the tenant. It is
// a no-op when the tenant already has one (key rotation is not supported for
// ephemeral quick tunnels).
func (s *Store) CreateSigningKey(tenantSlug, privateKeyPEM string) error {
	_, err := s.db.Exec(
		`INSERT OR IGNORE INTO signing_keys (tenant_slug, private_key_pem, created_at)
		 VALUES (?, ?, ?)`,
		tenantSlug, privateKeyPEM, time.Now().Unix())
	return err
}

// GetSigningKey returns the PEM-encoded EC private key for the tenant, or
// ErrNotFound.
func (s *Store) GetSigningKey(tenantSlug string) (string, error) {
	var pem string
	err := s.db.QueryRow(
		`SELECT private_key_pem FROM signing_keys WHERE tenant_slug = ?`, tenantSlug).
		Scan(&pem)
	if errors.Is(err, sql.ErrNoRows) {
		return "", ErrNotFound
	}
	return pem, err
}

// CreateOAuthClient registers a DCR client under the tenant. redirectURIs is a
// JSON array of strings.
func (s *Store) CreateOAuthClient(tenantSlug, clientID, redirectURIs string) error {
	_, err := s.db.Exec(
		`INSERT INTO oauth_clients (tenant_slug, client_id, redirect_uris, created_at)
		 VALUES (?, ?, ?, ?)`,
		tenantSlug, clientID, redirectURIs, time.Now().Unix())
	if isUniqueViolation(err) {
		return ErrExists
	}
	return err
}

// GetOAuthClient returns the redirect URIs JSON for a registered client, or
// ErrNotFound.
func (s *Store) GetOAuthClient(tenantSlug, clientID string) (redirectURIs string, err error) {
	err = s.db.QueryRow(
		`SELECT redirect_uris FROM oauth_clients WHERE tenant_slug = ? AND client_id = ?`,
		tenantSlug, clientID).Scan(&redirectURIs)
	if errors.Is(err, sql.ErrNoRows) {
		return "", ErrNotFound
	}
	return redirectURIs, err
}

// CreateAuthCode stores a one-time authorization code. codeHash is the SHA-256
// hex digest of the code; the plaintext is never stored.
func (s *Store) CreateAuthCode(codeHash, tenantSlug, clientID, redirectURI, codeChallenge string, expiresAt time.Time) error {
	_, err := s.db.Exec(
		`INSERT INTO auth_codes (code_hash, tenant_slug, client_id, redirect_uri, code_challenge, expires_at)
		 VALUES (?, ?, ?, ?, ?, ?)`,
		codeHash, tenantSlug, clientID, redirectURI, codeChallenge, expiresAt.Unix())
	return err
}

// ConsumeAuthCode atomically marks the code used and returns it. ErrNotFound
// when the code does not exist, is expired, or was already used.
func (s *Store) ConsumeAuthCode(codeHash string, now time.Time) (tenantSlug, clientID, redirectURI, codeChallenge string, err error) {
	res, err := s.db.Exec(
		`UPDATE auth_codes SET used_at = ?
		 WHERE code_hash = ? AND used_at IS NULL AND expires_at > ?`,
		now.Unix(), codeHash, now.Unix())
	if err != nil {
		return "", "", "", "", err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return "", "", "", "", ErrNotFound
	}
	err = s.db.QueryRow(
		`SELECT tenant_slug, client_id, redirect_uri, code_challenge
		 FROM auth_codes WHERE code_hash = ?`, codeHash).
		Scan(&tenantSlug, &clientID, &redirectURI, &codeChallenge)
	return tenantSlug, clientID, redirectURI, codeChallenge, err
}
