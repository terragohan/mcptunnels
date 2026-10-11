// Package stored1 implements store.API over Cloudflare D1's REST API, so
// tunneld can keep its state in one remote SQLite database instead of a
// local file. It uses only the standard library's net/http.
//
// Assumptions and differences from the local SQLite store (store.Store):
//
//   - Read-your-writes: every statement executes against the database
//     primary via the REST API, so a query always observes the effects of
//     the store's own preceding writes. This assumes tunneld is the only
//     writer of the database.
//   - One statement per request: the D1 query endpoint accepts a single
//     {"sql", "params"} object per call (batched arrays are rejected with
//     HTTP 400; batching exists only on the separate /batch endpoint, which
//     this client does not use). Multi-statement operations therefore issue
//     ordered sequential requests with NO rollback: when statement k fails,
//     statements 1..k-1 stay committed and k+1.. are never issued. Statement
//     order is chosen so a partial sequence leaves safe intermediate state —
//     QuickRateHit prunes old windows before incrementing, and
//     DeleteExpiredTenants deletes one slug per request so a mid-sequence
//     failure only leaves other expired tenants behind (the next sweep
//     retries them).
//   - Times are stored as INTEGER unix seconds, byte-for-byte the way the
//     SQLite store writes them, and compared with plain integer comparisons
//     (no unixepoch() wrappers — the columns are integers). Readers
//     defensively tolerate RFC3339 text (a stray row written by an older
//     client) but every write is an integer epoch.
//   - D1's REST rate limits (~50 queries/s per database) sit far above
//     tunneld's store traffic, which is confined to tunnel creation and
//     OAuth flows — proxied requests never touch the store.
package stored1

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/terragohan/mcptunnels/internal/store"
)

// defaultBaseURL is the Cloudflare v4 API origin; apiBaseURL is a variable
// so tests can point the client at an httptest server.
const defaultBaseURL = "https://api.cloudflare.com/client/v4"

var apiBaseURL = defaultBaseURL

// Config identifies the D1 database and authenticates the client. APIToken
// is a Cloudflare API token (or API key) with D1 edit rights; callers
// resolve it from the environment — it never comes from the yaml file.
type Config struct {
	AccountID  string
	DatabaseID string
	APIToken   string
}

// Store implements store.API over the D1 query endpoint. It is safe for
// concurrent use.
type Store struct {
	url    string
	token  string
	client *http.Client
}

var _ store.API = (*Store)(nil)

// New builds a Store and creates the schema (CREATE TABLE IF NOT EXISTS) in
// the D1 database, mirroring store.Open. It fails when the database is
// unreachable or the token is rejected, so a misconfiguration stops startup
// instead of surfacing later.
func New(cfg Config) (*Store, error) {
	if cfg.AccountID == "" {
		return nil, errors.New("stored1: account id is required")
	}
	if cfg.DatabaseID == "" {
		return nil, errors.New("stored1: database id is required")
	}
	if cfg.APIToken == "" {
		return nil, errors.New("stored1: api token is required")
	}
	s := &Store{
		url: fmt.Sprintf("%s/accounts/%s/d1/database/%s/query",
			apiBaseURL, cfg.AccountID, cfg.DatabaseID),
		token:  cfg.APIToken,
		client: &http.Client{Timeout: 30 * time.Second},
	}
	if err := s.migrate(); err != nil {
		return nil, err
	}
	return s, nil
}

// Close releases idle HTTP connections. D1 is remote; there is nothing else
// to tear down.
func (s *Store) Close() error {
	if tr, ok := s.client.Transport.(*http.Transport); ok {
		tr.CloseIdleConnections()
	}
	return nil
}

// migrate creates the tables a fresh D1 database needs. The DDL is the
// effective schema of a fresh SQLite database — including the services
// auth_mode/password_hash columns the SQLite store adds via ALTER TABLE —
// declared inline since a D1 database is only ever written by this package,
// starting empty, and has no legacy tables to migrate. D1 enforces the
// foreign keys declared here itself, so the cascading deletes of the SQLite
// store work unchanged.
func (s *Store) migrate() error {
	ddl := []statement{
		{SQL: `CREATE TABLE IF NOT EXISTS tenants (
			slug         TEXT PRIMARY KEY,
			display_name TEXT NOT NULL DEFAULT '',
			created_at   INTEGER NOT NULL,
			expires_at   INTEGER
		)`},
		{SQL: `CREATE TABLE IF NOT EXISTS services (
			tenant_slug     TEXT NOT NULL REFERENCES tenants(slug) ON DELETE CASCADE,
			name            TEXT NOT NULL,
			agent_key_hash  TEXT NOT NULL,
			created_at      INTEGER NOT NULL,
			auth_mode       TEXT NOT NULL DEFAULT 'oauth',
			password_hash   TEXT NOT NULL DEFAULT '',
			PRIMARY KEY (tenant_slug, name)
		)`},
		{SQL: `CREATE TABLE IF NOT EXISTS quick_rate (
			ip           TEXT NOT NULL,
			window_start INTEGER NOT NULL,
			count        INTEGER NOT NULL,
			PRIMARY KEY (ip, window_start)
		)`},
		{SQL: `CREATE TABLE IF NOT EXISTS signing_keys (
			tenant_slug     TEXT PRIMARY KEY REFERENCES tenants(slug) ON DELETE CASCADE,
			private_key_pem TEXT NOT NULL,
			created_at      INTEGER NOT NULL
		)`},
		{SQL: `CREATE TABLE IF NOT EXISTS oauth_clients (
			tenant_slug   TEXT NOT NULL REFERENCES tenants(slug) ON DELETE CASCADE,
			client_id     TEXT NOT NULL,
			redirect_uris TEXT NOT NULL DEFAULT '[]',
			created_at    INTEGER NOT NULL,
			PRIMARY KEY (tenant_slug, client_id)
		)`},
		{SQL: `CREATE TABLE IF NOT EXISTS auth_codes (
			code_hash      TEXT PRIMARY KEY,
			tenant_slug    TEXT NOT NULL REFERENCES tenants(slug) ON DELETE CASCADE,
			client_id      TEXT NOT NULL,
			redirect_uri   TEXT NOT NULL,
			code_challenge TEXT NOT NULL,
			expires_at     INTEGER NOT NULL,
			used_at        INTEGER
		)`},
	}
	if _, err := s.query(ddl...); err != nil {
		return fmt.Errorf("stored1: migrate: %w", err)
	}
	return nil
}

// --- D1 wire protocol ---

// statement is one SQL statement plus its bound parameters — the whole
// request body of the query endpoint, which accepts exactly one statement
// object per call.
type statement struct {
	SQL    string `json:"sql"`
	Params []any  `json:"params"`
}

type apiError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

// stmtResult is the per-statement result of the query endpoint; the response
// envelope carries it as result[0].
type stmtResult struct {
	Success bool             `json:"success"`
	Results []map[string]any `json:"results"`
	Meta    struct {
		RowsRead    int64 `json:"rows_read"`
		RowsWritten int64 `json:"rows_written"`
	} `json:"meta"`
	Errors []apiError `json:"errors"`
}

type queryResponse struct {
	Success bool         `json:"success"`
	Errors  []apiError   `json:"errors"`
	Result  []stmtResult `json:"result"`
}

// query executes stmts as sequential per-statement requests, in order, and
// returns the per-statement results. The D1 query endpoint accepts exactly
// one statement object per HTTP call, so there is no batching. Execution
// stops at the first failed statement and never rolls back earlier ones:
// statements 1..k-1 stay committed and k+1.. are never issued. The returned
// results cover the statements that ran and the error describes the first
// failure.
func (s *Store) query(stmts ...statement) ([]stmtResult, error) {
	results := make([]stmtResult, 0, len(stmts))
	for i, st := range stmts {
		res, err := s.exec(st)
		if err != nil {
			return results, fmt.Errorf("d1: statement %d failed: %w", i+1, err)
		}
		results = append(results, res)
	}
	return results, nil
}

// exec runs one statement through the D1 query endpoint: a single
// {"sql", "params"} object per request, response envelope
// {success, result: [{success, results, meta, errors}]}.
func (s *Store) exec(st statement) (stmtResult, error) {
	body, err := json.Marshal(st)
	if err != nil {
		return stmtResult{}, err
	}
	req, err := http.NewRequest(http.MethodPost, s.url, bytes.NewReader(body))
	if err != nil {
		return stmtResult{}, err
	}
	req.Header.Set("Authorization", "Bearer "+s.token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := s.client.Do(req)
	if err != nil {
		return stmtResult{}, fmt.Errorf("d1: request: %w", err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return stmtResult{}, fmt.Errorf("d1: read response: %w", err)
	}
	var qr queryResponse
	if err := json.Unmarshal(raw, &qr); err != nil {
		return stmtResult{}, fmt.Errorf("d1: HTTP %d: %s", resp.StatusCode, truncate(string(raw)))
	}
	if resp.StatusCode != http.StatusOK || !qr.Success {
		return stmtResult{}, fmt.Errorf("d1: HTTP %d: %s", resp.StatusCode, joinErrors(qr.Errors))
	}
	if len(qr.Result) == 0 {
		return stmtResult{}, errors.New("d1: empty result")
	}
	if !qr.Result[0].Success {
		return stmtResult{}, errors.New(joinErrors(qr.Result[0].Errors))
	}
	return qr.Result[0], nil
}

func joinErrors(errs []apiError) string {
	msgs := make([]string, 0, len(errs))
	for _, e := range errs {
		msgs = append(msgs, e.Message)
	}
	if len(msgs) == 0 {
		return "unknown error"
	}
	return strings.Join(msgs, "; ")
}

func truncate(s string) string {
	const max = 200
	if len(s) > max {
		return s[:max] + "…"
	}
	return s
}

// --- value encoding ---

// timeCol decodes a D1 result value into a time.Time. Values written by this
// package are INTEGER unix seconds (identical to the SQLite store); RFC3339
// strings are tolerated defensively, e.g. a stray row written by the first
// stored1 revision.
func timeCol(v any) (time.Time, error) {
	switch x := v.(type) {
	case string:
		if t, err := time.Parse(time.RFC3339, x); err == nil {
			return t, nil
		}
		if n, err := strconv.ParseInt(x, 10, 64); err == nil {
			return time.Unix(n, 0), nil
		}
		return time.Time{}, fmt.Errorf("d1: unparseable time value %q", x)
	case float64:
		return time.Unix(int64(x), 0), nil
	default:
		return time.Time{}, fmt.Errorf("d1: unexpected time value %v (%T)", v, v)
	}
}

// optTime decodes a nullable time column.
func optTime(v any) (*time.Time, error) {
	if v == nil {
		return nil, nil
	}
	t, err := timeCol(v)
	if err != nil {
		return nil, err
	}
	return &t, nil
}

func strCol(row map[string]any, key string) (string, error) {
	v, ok := row[key].(string)
	if !ok {
		return "", fmt.Errorf("d1: column %q: want string, got %v (%T)", key, row[key], row[key])
	}
	return v, nil
}

func intCol(row map[string]any, key string) (int, error) {
	switch x := row[key].(type) {
	case float64:
		return int(x), nil
	case string:
		n, err := strconv.Atoi(x)
		if err != nil {
			return 0, fmt.Errorf("d1: column %q: %w", key, err)
		}
		return n, nil
	default:
		return 0, fmt.Errorf("d1: column %q: want number, got %v (%T)", key, row[key], row[key])
	}
}

// isUniqueViolation mirrors the SQLite store's UNIQUE-constraint detection.
// D1 reports SQLite error messages (e.g. "UNIQUE constraint failed:
// tenants.slug") in the statement's errors array.
func isUniqueViolation(err error) bool {
	return err != nil && strings.Contains(err.Error(), "UNIQUE constraint")
}

// --- Tenants ---

// CreateTenant creates a tenant without an expiry. It returns store.ErrExists
// if the slug is taken.
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
	_, err := s.query(statement{
		SQL:    `INSERT INTO tenants (slug, display_name, created_at, expires_at) VALUES (?, ?, ?, ?)`,
		Params: []any{slug, displayName, time.Now().Unix(), exp},
	})
	if err != nil {
		if isUniqueViolation(err) {
			return store.ErrExists
		}
		return fmt.Errorf("d1: create tenant: %w", err)
	}
	return nil
}

// GetTenant returns the tenant with the given slug, or store.ErrNotFound.
func (s *Store) GetTenant(slug string) (*store.Tenant, error) {
	res, err := s.query(statement{
		SQL:    `SELECT slug, display_name, created_at, expires_at FROM tenants WHERE slug = ?`,
		Params: []any{slug},
	})
	if err != nil {
		return nil, fmt.Errorf("d1: get tenant: %w", err)
	}
	rows := res[0].Results
	if len(rows) == 0 {
		return nil, store.ErrNotFound
	}
	row := rows[0]
	out := &store.Tenant{}
	if out.Slug, err = strCol(row, "slug"); err != nil {
		return nil, err
	}
	if out.DisplayName, err = strCol(row, "display_name"); err != nil {
		return nil, err
	}
	if out.CreatedAt, err = timeCol(row["created_at"]); err != nil {
		return nil, err
	}
	if out.ExpiresAt, err = optTime(row["expires_at"]); err != nil {
		return nil, err
	}
	return out, nil
}

// DeleteTenant removes a tenant and, via ON DELETE CASCADE, its services. It
// reports false when the tenant did not exist.
func (s *Store) DeleteTenant(slug string) (bool, error) {
	res, err := s.query(statement{
		SQL:    `DELETE FROM tenants WHERE slug = ?`,
		Params: []any{slug},
	})
	if err != nil {
		return false, fmt.Errorf("d1: delete tenant: %w", err)
	}
	// D1 counts rows cascaded through ON DELETE CASCADE in rows_written
	// (a tenant with services/keys reports > 1), so any positive count means
	// the tenant existed and was deleted.
	return res[0].Meta.RowsWritten >= 1, nil
}

// DeleteExpiredTenants removes every ephemeral tenant whose expires_at is at
// or before now (cascading like DeleteTenant) and returns the deleted slugs.
// The DELETEs are issued as sequential per-slug requests; a mid-sequence
// failure leaves the remaining expired tenants in place for the next sweep
// (and is reported, like the SQLite store reports a mid-loop failure).
func (s *Store) DeleteExpiredTenants(now time.Time) ([]string, error) {
	res, err := s.query(statement{
		SQL:    `SELECT slug FROM tenants WHERE expires_at IS NOT NULL AND expires_at <= ?`,
		Params: []any{now.Unix()},
	})
	if err != nil {
		return nil, fmt.Errorf("d1: list expired tenants: %w", err)
	}
	var slugs []string
	for _, row := range res[0].Results {
		slug, err := strCol(row, "slug")
		if err != nil {
			return nil, err
		}
		slugs = append(slugs, slug)
	}
	if len(slugs) == 0 {
		return nil, nil
	}
	stmts := make([]statement, len(slugs))
	for i, slug := range slugs {
		stmts[i] = statement{
			SQL:    `DELETE FROM tenants WHERE slug = ?`,
			Params: []any{slug},
		}
	}
	if _, err := s.query(stmts...); err != nil {
		return slugs, fmt.Errorf("d1: delete expired tenants: %w", err)
	}
	return slugs, nil
}

// CountLiveTenants returns the number of non-expired ephemeral tenants
// (expires_at set and still in the future).
func (s *Store) CountLiveTenants(now time.Time) (int, error) {
	res, err := s.query(statement{
		SQL:    `SELECT COUNT(*) AS n FROM tenants WHERE expires_at IS NOT NULL AND expires_at > ?`,
		Params: []any{now.Unix()},
	})
	if err != nil {
		return 0, fmt.Errorf("d1: count live tenants: %w", err)
	}
	if len(res[0].Results) == 0 {
		return 0, nil
	}
	return intCol(res[0].Results[0], "n")
}

// --- Quick-tunnel rate limiting ---

// QuickRateHit records one quick-tunnel creation attempt from ip in the
// fixed one-hour window containing now and returns the window's hit count.
// The three statements (prune old windows, increment, read back) are issued
// as ordered sequential requests, so a partial failure never increments
// without the read-back: if the upsert fails the sequence stops and the
// count is left untouched (only the harmless prune committed), matching the
// all-or-error behavior of the SQLite store.
func (s *Store) QuickRateHit(ip string, now time.Time) (int, error) {
	window := now.Unix() / 3600
	res, err := s.query(
		statement{
			SQL:    `DELETE FROM quick_rate WHERE window_start < ?`,
			Params: []any{window - 2},
		},
		statement{
			SQL: `INSERT INTO quick_rate (ip, window_start, count) VALUES (?, ?, 1)
				ON CONFLICT (ip, window_start) DO UPDATE SET count = count + 1`,
			Params: []any{ip, window},
		},
		statement{
			SQL:    `SELECT count FROM quick_rate WHERE ip = ? AND window_start = ?`,
			Params: []any{ip, window},
		},
	)
	if err != nil {
		return 0, fmt.Errorf("d1: quick rate hit: %w", err)
	}
	if len(res[2].Results) == 0 {
		return 0, fmt.Errorf("d1: quick rate hit: counter row missing after upsert")
	}
	return intCol(res[2].Results[0], "count")
}

const agentKeyPrefix = "tun_agent_"

// newAgentKey generates a plaintext agent key and its bcrypt hash. The key
// format matches the SQLite store's exactly (`tun_agent_<48 hex chars>`).
func newAgentKey() (plaintext, hash string, err error) {
	b := make([]byte, 24)
	if _, err := rand.Read(b); err != nil {
		return "", "", fmt.Errorf("d1: generate agent key: %w", err)
	}
	plaintext = agentKeyPrefix + "_" + hex.EncodeToString(b)
	hash, err = store.HashSecret(plaintext)
	if err != nil {
		return "", "", err
	}
	return plaintext, hash, nil
}

// --- Services ---

// CreateService creates a service under a tenant, generating its agent key;
// the plaintext key is returned once and only its bcrypt hash is stored.
// ErrExists is returned when (tenant_slug, name) is taken; ErrNotFound when
// the tenant does not exist. The tenant check is folded into the INSERT
// (INSERT ... SELECT ... WHERE EXISTS) so the whole method is a single
// statement: a missing tenant writes zero rows, a duplicate key surfaces as
// the same UNIQUE violation the SQLite store produces.
func (s *Store) CreateService(tenantSlug string, svc *store.Service) (string, error) {
	plaintext, hash, err := newAgentKey()
	if err != nil {
		return "", err
	}
	svc.AgentKeyHash = hash
	svc.CreatedAt = time.Now()
	if svc.AuthMode == "" {
		svc.AuthMode = "oauth"
	}
	res, err := s.query(statement{
		SQL: `INSERT INTO services (tenant_slug, name, agent_key_hash, auth_mode, password_hash, created_at)
			SELECT ?, ?, ?, ?, ?, ?
			WHERE EXISTS (SELECT 1 FROM tenants WHERE slug = ?)`,
		Params: []any{tenantSlug, svc.Name, svc.AgentKeyHash, svc.AuthMode, svc.PasswordHash, svc.CreatedAt.Unix(), tenantSlug},
	})
	if err != nil {
		if isUniqueViolation(err) {
			return "", store.ErrExists
		}
		return "", fmt.Errorf("d1: create service: %w", err)
	}
	if res[0].Meta.RowsWritten == 0 {
		return "", store.ErrNotFound
	}
	return plaintext, nil
}

// GetService returns the named service of a tenant, or store.ErrNotFound.
func (s *Store) GetService(tenantSlug, name string) (*store.Service, error) {
	res, err := s.query(statement{
		SQL: `SELECT name, agent_key_hash, auth_mode, password_hash, created_at
			FROM services WHERE tenant_slug = ? AND name = ?`,
		Params: []any{tenantSlug, name},
	})
	if err != nil {
		return nil, fmt.Errorf("d1: get service: %w", err)
	}
	rows := res[0].Results
	if len(rows) == 0 {
		return nil, store.ErrNotFound
	}
	row := rows[0]
	out := &store.Service{}
	if out.Name, err = strCol(row, "name"); err != nil {
		return nil, err
	}
	if out.AgentKeyHash, err = strCol(row, "agent_key_hash"); err != nil {
		return nil, err
	}
	if out.AuthMode, err = strCol(row, "auth_mode"); err != nil {
		return nil, err
	}
	if out.PasswordHash, err = strCol(row, "password_hash"); err != nil {
		return nil, err
	}
	if out.CreatedAt, err = timeCol(row["created_at"]); err != nil {
		return nil, err
	}
	return out, nil
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
	return store.CheckSecret(svc.PasswordHash, password), nil
}

// ValidateAgentKey returns the service when key matches its stored agent key
// hash, store.ErrNotFound when the service does not exist, and
// store.ErrInvalidAgentKey when the key is wrong.
func (s *Store) ValidateAgentKey(tenantSlug, name, key string) (*store.Service, error) {
	svc, err := s.GetService(tenantSlug, name)
	if err != nil {
		return nil, err
	}
	if key == "" || !store.CheckSecret(svc.AgentKeyHash, key) {
		return nil, store.ErrInvalidAgentKey
	}
	return svc, nil
}

// --- OAuth ---

// CreateSigningKey stores a PEM-encoded EC private key for the tenant. It is
// a no-op when the tenant already has one (key rotation is not supported for
// ephemeral quick tunnels).
func (s *Store) CreateSigningKey(tenantSlug, privateKeyPEM string) error {
	_, err := s.query(statement{
		SQL: `INSERT OR IGNORE INTO signing_keys (tenant_slug, private_key_pem, created_at)
			VALUES (?, ?, ?)`,
		Params: []any{tenantSlug, privateKeyPEM, time.Now().Unix()},
	})
	if err != nil {
		return fmt.Errorf("d1: create signing key: %w", err)
	}
	return nil
}

// GetSigningKey returns the PEM-encoded EC private key for the tenant, or
// store.ErrNotFound.
func (s *Store) GetSigningKey(tenantSlug string) (string, error) {
	res, err := s.query(statement{
		SQL:    `SELECT private_key_pem FROM signing_keys WHERE tenant_slug = ?`,
		Params: []any{tenantSlug},
	})
	if err != nil {
		return "", fmt.Errorf("d1: get signing key: %w", err)
	}
	if len(res[0].Results) == 0 {
		return "", store.ErrNotFound
	}
	return strCol(res[0].Results[0], "private_key_pem")
}

// CreateOAuthClient registers a DCR client under the tenant. redirectURIs is
// a JSON array of strings.
func (s *Store) CreateOAuthClient(tenantSlug, clientID, redirectURIs string) error {
	_, err := s.query(statement{
		SQL: `INSERT INTO oauth_clients (tenant_slug, client_id, redirect_uris, created_at)
			VALUES (?, ?, ?, ?)`,
		Params: []any{tenantSlug, clientID, redirectURIs, time.Now().Unix()},
	})
	if err != nil {
		if isUniqueViolation(err) {
			return store.ErrExists
		}
		return fmt.Errorf("d1: create oauth client: %w", err)
	}
	return nil
}

// GetOAuthClient returns the redirect URIs JSON for a registered client, or
// store.ErrNotFound.
func (s *Store) GetOAuthClient(tenantSlug, clientID string) (string, error) {
	res, err := s.query(statement{
		SQL:    `SELECT redirect_uris FROM oauth_clients WHERE tenant_slug = ? AND client_id = ?`,
		Params: []any{tenantSlug, clientID},
	})
	if err != nil {
		return "", fmt.Errorf("d1: get oauth client: %w", err)
	}
	if len(res[0].Results) == 0 {
		return "", store.ErrNotFound
	}
	return strCol(res[0].Results[0], "redirect_uris")
}

// CreateAuthCode stores a one-time authorization code. codeHash is the
// SHA-256 hex digest of the code; the plaintext is never stored.
func (s *Store) CreateAuthCode(codeHash, tenantSlug, clientID, redirectURI, codeChallenge string, expiresAt time.Time) error {
	_, err := s.query(statement{
		SQL: `INSERT INTO auth_codes (code_hash, tenant_slug, client_id, redirect_uri, code_challenge, expires_at)
			VALUES (?, ?, ?, ?, ?, ?)`,
		Params: []any{codeHash, tenantSlug, clientID, redirectURI, codeChallenge, expiresAt.Unix()},
	})
	if err != nil {
		return fmt.Errorf("d1: create auth code: %w", err)
	}
	return nil
}

// ConsumeAuthCode atomically marks the code used and returns it. ErrNotFound
// when the code does not exist, is expired, or was already used. The claim
// is a single UPDATE ... WHERE used_at IS NULL guarded by the expiry check;
// its affected-rows count (meta.rows_written) decides success, so a code can
// be consumed at most once even with concurrent callers. The follow-up
// SELECT is issued as a second request, only after the claim committed, so
// it always observes the claimed row; a zero-row claim returns ErrNotFound
// without the extra read.
func (s *Store) ConsumeAuthCode(codeHash string, now time.Time) (tenantSlug, clientID, redirectURI, codeChallenge string, err error) {
	nowUnix := now.Unix()
	res, err := s.query(statement{
		SQL: `UPDATE auth_codes SET used_at = ?
			WHERE code_hash = ? AND used_at IS NULL AND expires_at > ?`,
		Params: []any{nowUnix, codeHash, nowUnix},
	})
	if err != nil {
		return "", "", "", "", fmt.Errorf("d1: consume auth code: %w", err)
	}
	if res[0].Meta.RowsWritten == 0 {
		return "", "", "", "", store.ErrNotFound
	}
	res, err = s.query(statement{
		SQL:    `SELECT tenant_slug, client_id, redirect_uri, code_challenge FROM auth_codes WHERE code_hash = ?`,
		Params: []any{codeHash},
	})
	if err != nil {
		return "", "", "", "", fmt.Errorf("d1: read consumed auth code: %w", err)
	}
	if len(res[0].Results) != 1 {
		return "", "", "", "", fmt.Errorf("d1: consume auth code: row missing after successful claim")
	}
	row := res[0].Results[0]
	fail := func(err error) (string, string, string, string, error) {
		return "", "", "", "", err
	}
	if tenantSlug, err = strCol(row, "tenant_slug"); err != nil {
		return fail(err)
	}
	if clientID, err = strCol(row, "client_id"); err != nil {
		return fail(err)
	}
	if redirectURI, err = strCol(row, "redirect_uri"); err != nil {
		return fail(err)
	}
	if codeChallenge, err = strCol(row, "code_challenge"); err != nil {
		return fail(err)
	}
	return tenantSlug, clientID, redirectURI, codeChallenge, nil
}
