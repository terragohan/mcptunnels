package stored1

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/terragohan/mcptunnels/internal/store"
)

// --- fake D1 API server ---

// canned is the fake's canned outcome for one statement execution.
type canned struct {
	rows    []map[string]any
	written int64
	errMsg  string // if set, the statement fails with this SQLite-style message
}

// rule matches a statement by normalized SQL and, optionally, by params.
// Rules for one SQL string are consumed FIFO per request, so a statement
// executed repeatedly can return different outcomes in order.
type rule struct {
	when   func(params []any) bool
	result canned
}

// fakeD1 serves the real D1 query-endpoint contract: each request body is a
// SINGLE statement object {"sql", "params"}; the response envelope is
// {"success", "result": [{success, results, meta, errors}]}. An array body
// is rejected outright (that is the HTTP 400 shape the real API returns) and
// recorded so tests can fail loudly on it.
type fakeD1 struct {
	mu    sync.Mutex
	rules map[string][]rule

	auth     string
	path     string
	requests []statement // one entry per HTTP request, in order
	attempts []string    // normalized SQL of every executed statement (incl. failed ones)
	sawArray []string    // raw array bodies received — must stay empty

	httpErr string // when set, respond HTTP 400 with this error body instead
}

func normSQL(sql string) string { return strings.Join(strings.Fields(sql), " ") }

func (f *fakeD1) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.auth = r.Header.Get("Authorization")
	f.path = r.URL.Path
	if f.httpErr != "" {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(f.httpErr))
		return
	}
	raw, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 || trimmed[0] == '[' {
		f.sawArray = append(f.sawArray, string(trimmed))
		http.Error(w, "fake d1: expected a single statement object, got an array", http.StatusBadRequest)
		return
	}
	var st statement
	if err := json.Unmarshal(trimmed, &st); err != nil {
		http.Error(w, "fake d1: bad statement body", http.StatusBadRequest)
		return
	}
	f.requests = append(f.requests, st)
	key := normSQL(st.SQL)
	f.attempts = append(f.attempts, key)
	q := f.rules[key]
	matched := -1
	for i, rl := range q {
		if rl.when == nil || rl.when(st.Params) {
			matched = i
			break
		}
	}
	if matched < 0 {
		if strings.HasPrefix(key, "CREATE TABLE") {
			// Un-canned DDL (the New() migration) succeeds quietly.
			writeResult(w, okResult(nil, 0))
			return
		}
		writeResult(w, failResult("fake d1: no canned result for: "+key))
		return
	}
	rl := q[matched]
	f.rules[key] = append(q[:matched], q[matched+1:]...)
	if rl.result.errMsg != "" {
		writeResult(w, failResult(rl.result.errMsg))
		return // the client stops the sequence here; no rollback happens
	}
	writeResult(w, okResult(rl.result.rows, rl.result.written))
}

func okResult(rows []map[string]any, written int64) map[string]any {
	return map[string]any{
		"success": true,
		"results": rows,
		"meta":    map[string]any{"rows_read": len(rows), "rows_written": written},
	}
}

func failResult(msg string) map[string]any {
	return map[string]any{
		"success": false,
		"errors":  []map[string]any{{"code": 1, "message": msg}},
		"meta":    map[string]any{},
	}
}

func writeResult(w http.ResponseWriter, res map[string]any) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{"success": true, "result": []any{res}})
}

// newFake spins up a fake D1 API, points the package client at it, and
// returns the store plus the fake (for canned rules and assertions).
func newFake(t *testing.T, rules map[string][]rule) (*Store, *fakeD1) {
	t.Helper()
	f := &fakeD1{rules: rules}
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	old := apiBaseURL
	apiBaseURL = srv.URL
	t.Cleanup(func() { apiBaseURL = old })
	st, err := New(Config{AccountID: "acc-1", DatabaseID: "db-1", APIToken: "test-token"})
	if err != nil {
		t.Fatalf("stored1.New: %v", err)
	}
	t.Cleanup(func() { st.Close() })
	// Migration statements ran at construction; reset the execution trace
	// so tests only see their own calls.
	f.mu.Lock()
	f.attempts = nil
	f.mu.Unlock()
	t.Cleanup(func() {
		f.mu.Lock()
		defer f.mu.Unlock()
		if len(f.sawArray) > 0 {
			t.Errorf("client sent an ARRAY request body %q; the D1 query endpoint requires a single statement object", f.sawArray[0])
		}
	})
	return st, f
}

func (f *fakeD1) authHeader() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.auth
}

func (f *fakeD1) requestPath() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.path
}

func (f *fakeD1) numRequests() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.requests)
}

// requestsSnapshot returns every request received so far, one statement per
// HTTP request, in order.
func (f *fakeD1) requestsSnapshot() []statement {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]statement, len(f.requests))
	copy(out, f.requests)
	return out
}

func (f *fakeD1) attemptsSnapshot() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.attempts...)
}

// tailRequests returns the last n requests (n clamped to what exists).
func (f *fakeD1) tailRequests(n int) []statement {
	reqs := f.requestsSnapshot()
	if len(reqs) > n {
		reqs = reqs[len(reqs)-n:]
	}
	return reqs
}

// whenParam0 matches statements whose first param equals want.
func whenParam0(want any) func([]any) bool {
	return func(p []any) bool { return len(p) > 0 && p[0] == want }
}

func row(cols ...any) map[string]any {
	m := make(map[string]any, len(cols)/2)
	for i := 0; i < len(cols); i += 2 {
		m[cols[i].(string)] = cols[i+1]
	}
	return m
}

const (
	createTenantSQL = `INSERT INTO tenants (slug, display_name, created_at, expires_at) VALUES (?, ?, ?, ?)`
	getTenantSQL    = `SELECT slug, display_name, created_at, expires_at FROM tenants WHERE slug = ?`
	deleteTenantSQL = `DELETE FROM tenants WHERE slug = ?`
)

// --- tests ---

func TestNewValidatesConfig(t *testing.T) {
	cases := []Config{
		{DatabaseID: "db", APIToken: "tok"},
		{AccountID: "acc", APIToken: "tok"},
		{AccountID: "acc", DatabaseID: "db"},
	}
	for _, cfg := range cases {
		if _, err := New(cfg); err == nil {
			t.Fatalf("New(%+v): want error, got nil", cfg)
		}
	}
}

func TestNewMigratesAndSendsAuth(t *testing.T) {
	st, f := newFake(t, nil)
	_ = st
	if got := f.authHeader(); got != "Bearer test-token" {
		t.Fatalf("Authorization = %q, want %q", got, "Bearer test-token")
	}
	if got := f.requestPath(); got != "/accounts/acc-1/d1/database/db-1/query" {
		t.Fatalf("path = %q, want the query endpoint", got)
	}
	// The migration went out as six sequential single-statement requests.
	reqs := f.requestsSnapshot()
	if len(reqs) != 6 {
		t.Fatalf("migrate requests = %d, want 6", len(reqs))
	}
	for _, st := range reqs {
		if !strings.HasPrefix(normSQL(st.SQL), "CREATE TABLE IF NOT EXISTS") {
			t.Fatalf("migrate statement %q is not DDL", st.SQL)
		}
	}
}

func TestTenantLifecycle(t *testing.T) {
	exp := time.Now().Add(time.Hour).Truncate(time.Second)
	created := time.Date(2026, 10, 3, 0, 0, 0, 0, time.UTC)
	st, f := newFake(t, map[string][]rule{
		createTenantSQL: {
			{result: canned{written: 1}},
			{result: canned{written: 1}},
			{result: canned{errMsg: "UNIQUE constraint failed: tenants.slug"}},
			{result: canned{written: 1}},
		},
		getTenantSQL: {
			{when: whenParam0("q-temp"), result: canned{rows: []map[string]any{
				row("slug", "q-temp", "display_name", "quick tunnel", "created_at", created.Unix(), "expires_at", exp.Unix()),
			}}},
			{when: whenParam0("q-keep"), result: canned{rows: []map[string]any{
				row("slug", "q-keep", "display_name", "", "created_at", created.Unix(), "expires_at", nil),
			}}},
			{when: whenParam0("q-str"), result: canned{rows: []map[string]any{
				// Defensive read: an RFC3339 string row (e.g. written by the
				// first stored1 revision) still parses.
				row("slug", "q-str", "display_name", "", "created_at", created.Unix(), "expires_at", exp.UTC().Format(time.RFC3339)),
			}}},
			{result: canned{rows: nil}}, // any other slug
		},
	})

	if err := st.CreateTenant("q-keep", ""); err != nil {
		t.Fatal(err)
	}
	if err := st.CreateTenantExpiry("q-temp", "quick tunnel", &exp); err != nil {
		t.Fatal(err)
	}
	// Duplicate slug maps to ErrExists.
	if err := st.CreateTenant("q-keep", ""); !errors.Is(err, store.ErrExists) {
		t.Fatalf("duplicate tenant: %v, want ErrExists", err)
	}

	tn, err := st.GetTenant("q-temp")
	if err != nil {
		t.Fatal(err)
	}
	if tn.Slug != "q-temp" || tn.DisplayName != "quick tunnel" {
		t.Fatalf("tenant = %+v", tn)
	}
	if tn.ExpiresAt == nil || !tn.ExpiresAt.Equal(exp) {
		t.Fatalf("expires_at = %v, want %v", tn.ExpiresAt, exp)
	}
	if !tn.CreatedAt.Equal(created) {
		t.Fatalf("created_at = %v", tn.CreatedAt)
	}
	tn, err = st.GetTenant("q-keep")
	if err != nil {
		t.Fatal(err)
	}
	if tn.ExpiresAt != nil {
		t.Fatalf("non-expiring tenant expires_at = %v, want nil", tn.ExpiresAt)
	}

	// Unknown tenant maps to ErrNotFound.
	if _, err := st.GetTenant("q-nope"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("unknown tenant: %v, want ErrNotFound", err)
	}

	// Defensive read of a stray RFC3339 string row.
	if err := st.CreateTenant("q-str", ""); err != nil {
		t.Fatal(err)
	}
	tn, err = st.GetTenant("q-str")
	if err != nil {
		t.Fatal(err)
	}
	if tn.ExpiresAt == nil || !tn.ExpiresAt.Equal(exp) {
		t.Fatalf("string expires_at = %v, want %v", tn.ExpiresAt, exp)
	}

	// Timestamps bind as INTEGER unix seconds (JSON numbers); a nil expiry
	// binds as JSON null. Requests: 0-5=migrate DDL, 6..8=creates, 9..12=gets
	// (get q-nope included), 13..14=q-str create+get.
	reqs := f.requestsSnapshot()
	if got, ok := reqs[7].Params[3].(float64); !ok || got != float64(exp.Unix()) {
		t.Fatalf("expiry param = %v (%T), want integer %d", reqs[7].Params[3], reqs[7].Params[3], exp.Unix())
	}
	if got, ok := reqs[7].Params[2].(float64); !ok || got <= 1_000_000_000 {
		t.Fatalf("created_at param = %v (%T), want integer unix seconds", reqs[7].Params[2], reqs[7].Params[2])
	}
	if reqs[6].Params[3] != nil {
		t.Fatalf("nil expiry param = %v, want null", reqs[6].Params[3])
	}
}

func TestDeleteTenant(t *testing.T) {
	st, _ := newFake(t, map[string][]rule{
		deleteTenantSQL: {
			// D1 counts ON DELETE CASCADE children in rows_written: a tenant
			// with services/keys reports > 1 and must still count as deleted.
			{result: canned{written: 3}},
			{result: canned{written: 0}},
		},
	})
	ok, err := st.DeleteTenant("q-a")
	if err != nil || !ok {
		t.Fatalf("DeleteTenant = (%v, %v), want (true, nil)", ok, err)
	}
	ok, err = st.DeleteTenant("q-gone")
	if err != nil || ok {
		t.Fatalf("DeleteTenant missing = (%v, %v), want (false, nil)", ok, err)
	}
}

func TestDeleteExpiredTenants(t *testing.T) {
	st, f := newFake(t, map[string][]rule{
		`SELECT slug FROM tenants WHERE expires_at IS NOT NULL AND expires_at <= ?`: {
			{result: canned{rows: []map[string]any{row("slug", "q-a"), row("slug", "q-b")}}},
		},
		deleteTenantSQL: {
			{when: whenParam0("q-a"), result: canned{written: 1}},
			{when: whenParam0("q-b"), result: canned{written: 1}},
		},
	})
	slugs, err := st.DeleteExpiredTenants(time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if len(slugs) != 2 || slugs[0] != "q-a" || slugs[1] != "q-b" {
		t.Fatalf("slugs = %v, want [q-a q-b]", slugs)
	}
	// The sweep ran as three sequential single-statement requests: the
	// SELECT followed by one DELETE per slug, in slug order.
	tail := f.tailRequests(3)
	if len(tail) != 3 {
		t.Fatalf("tail = %d requests, want 3", len(tail))
	}
	if !strings.HasPrefix(normSQL(tail[0].SQL), "SELECT slug") {
		t.Fatalf("request 0 = %q, want the expired-tenant SELECT", tail[0].SQL)
	}
	if normSQL(tail[1].SQL) != deleteTenantSQL || tail[1].Params[0] != "q-a" {
		t.Fatalf("request 1 = %+v, want DELETE q-a", tail[1])
	}
	if normSQL(tail[2].SQL) != deleteTenantSQL || tail[2].Params[0] != "q-b" {
		t.Fatalf("request 2 = %+v, want DELETE q-b", tail[2])
	}
}

func TestDeleteExpiredTenantsPartialFailure(t *testing.T) {
	st, f := newFake(t, map[string][]rule{
		`SELECT slug FROM tenants WHERE expires_at IS NOT NULL AND expires_at <= ?`: {
			{result: canned{rows: []map[string]any{row("slug", "q-a"), row("slug", "q-b")}}},
		},
		deleteTenantSQL: {
			{when: whenParam0("q-a"), result: canned{written: 1}},
			{when: whenParam0("q-b"), result: canned{errMsg: "database is locked"}},
		},
	})
	slugs, err := st.DeleteExpiredTenants(time.Now())
	if err == nil {
		t.Fatal("partial sequence failure: want error")
	}
	// Like the SQLite store, the found slugs are returned with the error.
	if len(slugs) != 2 {
		t.Fatalf("slugs = %v, want both slugs alongside the error", slugs)
	}
	// Sequential requests with no rollback: q-a's DELETE committed, q-b's
	// failed, and the client issued nothing further. Total: 6 migrate +
	// SELECT + 2 DELETEs.
	if n := f.numRequests(); n != 9 {
		t.Fatalf("requests = %d, want 9 (6 migrate + SELECT + 2 DELETEs)", n)
	}
	attempts := f.attemptsSnapshot()
	if len(attempts) != 3 || !strings.HasPrefix(attempts[1], "DELETE") || !strings.HasPrefix(attempts[2], "DELETE") {
		t.Fatalf("attempts = %v, want [SELECT, DELETE, DELETE]", attempts)
	}
}

func TestCountLiveTenants(t *testing.T) {
	st, _ := newFake(t, map[string][]rule{
		`SELECT COUNT(*) AS n FROM tenants WHERE expires_at IS NOT NULL AND expires_at > ?`: {
			{result: canned{rows: []map[string]any{row("n", 3)}}},
			{result: canned{rows: []map[string]any{row("n", 0)}}},
		},
	})
	n, err := st.CountLiveTenants(time.Now())
	if err != nil || n != 3 {
		t.Fatalf("CountLiveTenants = (%d, %v), want (3, nil)", n, err)
	}
	n, err = st.CountLiveTenants(time.Now())
	if err != nil || n != 0 {
		t.Fatalf("empty CountLiveTenants = (%d, %v), want (0, nil)", n, err)
	}
}

func TestQuickRateHit(t *testing.T) {
	st, f := newFake(t, map[string][]rule{
		`DELETE FROM quick_rate WHERE window_start < ?`: {{result: canned{written: 0}}},
		`INSERT INTO quick_rate (ip, window_start, count) VALUES (?, ?, 1) ON CONFLICT (ip, window_start) DO UPDATE SET count = count + 1`: {
			{result: canned{written: 1}},
		},
		`SELECT count FROM quick_rate WHERE ip = ? AND window_start = ?`: {
			{result: canned{rows: []map[string]any{row("count", 7)}}},
		},
	})
	n, err := st.QuickRateHit("203.0.113.1", time.Now())
	if err != nil || n != 7 {
		t.Fatalf("QuickRateHit = (%d, %v), want (7, nil)", n, err)
	}
	// Prune, upsert, and read-back were three sequential requests, in that
	// order.
	tail := f.tailRequests(3)
	if len(tail) != 3 {
		t.Fatalf("tail = %d requests, want 3", len(tail))
	}
	if want := "DELETE FROM quick_rate"; !strings.HasPrefix(normSQL(tail[0].SQL), want) {
		t.Fatalf("request 0 = %q, want %q...", tail[0].SQL, want)
	}
	if want := "INSERT INTO quick_rate"; !strings.HasPrefix(normSQL(tail[1].SQL), want) {
		t.Fatalf("request 1 = %q, want %q...", tail[1].SQL, want)
	}
	if want := "SELECT count"; !strings.HasPrefix(normSQL(tail[2].SQL), want) {
		t.Fatalf("request 2 = %q, want %q...", tail[2].SQL, want)
	}
	// The window is the unix hour bucket.
	now := time.Now()
	if got := tail[1].Params[1].(float64); got != float64(now.Unix()/3600) {
		t.Fatalf("window param = %v, want %d", got, now.Unix()/3600)
	}
}

func TestQuickRateHitUpsertFailure(t *testing.T) {
	st, f := newFake(t, map[string][]rule{
		`DELETE FROM quick_rate WHERE window_start < ?`: {{result: canned{written: 0}}},
		`INSERT INTO quick_rate (ip, window_start, count) VALUES (?, ?, 1) ON CONFLICT (ip, window_start) DO UPDATE SET count = count + 1`: {
			{result: canned{errMsg: "database is locked"}},
		},
	})
	if _, err := st.QuickRateHit("203.0.113.1", time.Now()); err == nil {
		t.Fatal("upsert failure: want error")
	}
	// The read-back after the failed upsert was never requested.
	attempts := f.attemptsSnapshot()
	if len(attempts) != 2 || !strings.HasPrefix(attempts[0], "DELETE") || !strings.HasPrefix(attempts[1], "INSERT") {
		t.Fatalf("attempts = %v, want [prune, upsert] only", attempts)
	}
}

func TestCreateService(t *testing.T) {
	createSQL := normSQL(`INSERT INTO services (tenant_slug, name, agent_key_hash, auth_mode, password_hash, created_at)
		SELECT ?, ?, ?, ?, ?, ?
		WHERE EXISTS (SELECT 1 FROM tenants WHERE slug = ?)`)
	st, _ := newFake(t, map[string][]rule{
		createSQL: {
			{result: canned{written: 1}},
			{result: canned{written: 0}}, // tenant missing
			{result: canned{errMsg: "UNIQUE constraint failed: services.tenant_slug, services.name"}},
		},
	})

	svc := &store.Service{Name: "mcp"}
	key, err := st.CreateService("q-ok", svc)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(key, "tun_agent_") {
		t.Fatalf("agent key %q lacks tun_agent_ prefix", key)
	}
	if svc.AuthMode != "oauth" || svc.AgentKeyHash == "" || svc.CreatedAt.IsZero() {
		t.Fatalf("svc not populated: %+v", svc)
	}

	// Missing tenant: the WHERE EXISTS guard writes zero rows → ErrNotFound.
	if _, err := st.CreateService("q-nope", &store.Service{Name: "mcp"}); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("missing tenant: %v, want ErrNotFound", err)
	}
	// Duplicate (tenant, name) → UNIQUE violation → ErrExists.
	if _, err := st.CreateService("q-ok", &store.Service{Name: "mcp"}); !errors.Is(err, store.ErrExists) {
		t.Fatalf("duplicate service: %v, want ErrExists", err)
	}
}

func TestServiceReadsAndValidation(t *testing.T) {
	getServiceSQL := normSQL(`SELECT name, agent_key_hash, auth_mode, password_hash, created_at
		FROM services WHERE tenant_slug = ? AND name = ?`)
	hash, err := store.HashSecret("testpass")
	if err != nil {
		t.Fatal(err)
	}
	svcHash, err := store.HashSecret("tun_agent_keyvalue")
	if err != nil {
		t.Fatal(err)
	}
	createdUnix := time.Date(2026, 10, 3, 0, 0, 0, 0, time.UTC).Unix()
	st, _ := newFake(t, map[string][]rule{
		getServiceSQL: {
			// "mcp" is fetched by GetService, two ValidatePassword calls,
			// and two ValidateAgentKey calls.
			{when: func(p []any) bool { return p[1] == "mcp" }, result: canned{rows: []map[string]any{
				row("name", "mcp", "agent_key_hash", svcHash, "auth_mode", "oauth", "password_hash", hash, "created_at", createdUnix),
			}}},
			{when: func(p []any) bool { return p[1] == "mcp" }, result: canned{rows: []map[string]any{
				row("name", "mcp", "agent_key_hash", svcHash, "auth_mode", "oauth", "password_hash", hash, "created_at", createdUnix),
			}}},
			{when: func(p []any) bool { return p[1] == "mcp" }, result: canned{rows: []map[string]any{
				row("name", "mcp", "agent_key_hash", svcHash, "auth_mode", "oauth", "password_hash", hash, "created_at", createdUnix),
			}}},
			{when: func(p []any) bool { return p[1] == "mcp" }, result: canned{rows: []map[string]any{
				row("name", "mcp", "agent_key_hash", svcHash, "auth_mode", "oauth", "password_hash", hash, "created_at", createdUnix),
			}}},
			{when: func(p []any) bool { return p[1] == "mcp" }, result: canned{rows: []map[string]any{
				row("name", "mcp", "agent_key_hash", svcHash, "auth_mode", "oauth", "password_hash", hash, "created_at", createdUnix),
			}}},
			{when: func(p []any) bool { return p[1] == "open" }, result: canned{rows: []map[string]any{
				row("name", "open", "agent_key_hash", svcHash, "auth_mode", "open", "password_hash", "", "created_at", createdUnix),
			}}},
			{result: canned{rows: nil}}, // unknown service
		},
	})

	svc, err := st.GetService("q-a", "mcp")
	if err != nil {
		t.Fatal(err)
	}
	if svc.Name != "mcp" || svc.AuthMode != "oauth" || svc.PasswordHash != hash {
		t.Fatalf("svc = %+v", svc)
	}

	ok, err := st.ValidatePassword("q-a", "mcp", "testpass")
	if err != nil || !ok {
		t.Fatalf("ValidatePassword right = (%v, %v), want (true, nil)", ok, err)
	}
	ok, err = st.ValidatePassword("q-a", "mcp", "wrong")
	if err != nil || ok {
		t.Fatalf("ValidatePassword wrong = (%v, %v), want (false, nil)", ok, err)
	}
	// Open service: empty password hash validates anything.
	ok, err = st.ValidatePassword("q-a", "open", "anything")
	if err != nil || !ok {
		t.Fatalf("ValidatePassword open = (%v, %v), want (true, nil)", ok, err)
	}

	got, err := st.ValidateAgentKey("q-a", "mcp", "tun_agent_keyvalue")
	if err != nil || got.Name != "mcp" {
		t.Fatalf("ValidateAgentKey = (%+v, %v)", got, err)
	}
	if _, err := st.ValidateAgentKey("q-a", "mcp", "nope"); !errors.Is(err, store.ErrInvalidAgentKey) {
		t.Fatalf("wrong key: %v, want ErrInvalidAgentKey", err)
	}
	if _, err := st.ValidateAgentKey("q-a", "other", "tun_agent_keyvalue"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("unknown service: %v, want ErrNotFound", err)
	}
}

func TestSigningKey(t *testing.T) {
	const pem = "-----BEGIN EC PRIVATE KEY-----\nfake\n-----END EC PRIVATE KEY-----"
	st, _ := newFake(t, map[string][]rule{
		normSQL(`INSERT OR IGNORE INTO signing_keys (tenant_slug, private_key_pem, created_at)
			VALUES (?, ?, ?)`): {{result: canned{written: 1}}},
		`SELECT private_key_pem FROM signing_keys WHERE tenant_slug = ?`: {
			{when: whenParam0("q-key"), result: canned{rows: []map[string]any{row("private_key_pem", pem)}}},
			{result: canned{rows: nil}},
		},
	})
	if err := st.CreateSigningKey("q-key", pem); err != nil {
		t.Fatal(err)
	}
	got, err := st.GetSigningKey("q-key")
	if err != nil || got != pem {
		t.Fatalf("GetSigningKey = (%q, %v)", got, err)
	}
	if _, err := st.GetSigningKey("q-nope"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("missing key: %v, want ErrNotFound", err)
	}
}

func TestOAuthClient(t *testing.T) {
	uris := `["https://example.com/cb"]`
	st, _ := newFake(t, map[string][]rule{
		normSQL(`INSERT INTO oauth_clients (tenant_slug, client_id, redirect_uris, created_at)
			VALUES (?, ?, ?, ?)`): {
			{result: canned{written: 1}},
			{result: canned{errMsg: "UNIQUE constraint failed: oauth_clients.tenant_slug, oauth_clients.client_id"}},
		},
		`SELECT redirect_uris FROM oauth_clients WHERE tenant_slug = ? AND client_id = ?`: {
			{result: canned{rows: []map[string]any{row("redirect_uris", uris)}}},
			{result: canned{rows: nil}},
		},
	})
	if err := st.CreateOAuthClient("q-cli", "client1", uris); err != nil {
		t.Fatal(err)
	}
	if err := st.CreateOAuthClient("q-cli", "client1", uris); !errors.Is(err, store.ErrExists) {
		t.Fatalf("duplicate client: %v, want ErrExists", err)
	}
	got, err := st.GetOAuthClient("q-cli", "client1")
	if err != nil || got != uris {
		t.Fatalf("GetOAuthClient = (%q, %v)", got, err)
	}
	if _, err := st.GetOAuthClient("q-cli", "nope"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("unknown client: %v, want ErrNotFound", err)
	}
}

func TestAuthCodeLifecycle(t *testing.T) {
	const (
		updateSQL = `UPDATE auth_codes SET used_at = ? WHERE code_hash = ? AND used_at IS NULL AND expires_at > ?`
		selectSQL = `SELECT tenant_slug, client_id, redirect_uri, code_challenge FROM auth_codes WHERE code_hash = ?`
		insertSQL = `INSERT INTO auth_codes (code_hash, tenant_slug, client_id, redirect_uri, code_challenge, expires_at) VALUES (?, ?, ?, ?, ?, ?)`
	)
	st, f := newFake(t, map[string][]rule{
		insertSQL: {{result: canned{written: 1}}, {result: canned{written: 1}}},
		updateSQL: {
			{result: canned{written: 1}}, // first consume claims
			{result: canned{written: 0}}, // second consume: already used
			{result: canned{written: 0}}, // expired
		},
		// Only the successful claim issues the follow-up SELECT.
		selectSQL: {
			{result: canned{rows: []map[string]any{
				row("tenant_slug", "q-code", "client_id", "client1", "redirect_uri", "https://example.com/cb", "code_challenge", "challenge1"),
			}}},
		},
	})

	expires := time.Now().Add(time.Minute)
	if err := st.CreateAuthCode("hash1", "q-code", "client1", "https://example.com/cb", "challenge1", expires); err != nil {
		t.Fatal(err)
	}

	tenant, clientID, redirectURI, challenge, err := st.ConsumeAuthCode("hash1", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if tenant != "q-code" || clientID != "client1" || redirectURI != "https://example.com/cb" || challenge != "challenge1" {
		t.Fatalf("ConsumeAuthCode = (%q, %q, %q, %q)", tenant, clientID, redirectURI, challenge)
	}
	// Claim and read-back were two sequential requests, in that order.
	tail := f.tailRequests(2)
	if len(tail) != 2 || normSQL(tail[0].SQL) != updateSQL || normSQL(tail[1].SQL) != selectSQL {
		t.Fatalf("consume requests = %+v, want [UPDATE, SELECT]", tail)
	}

	// Reuse, then an expired code: the UPDATE matches zero rows → ErrNotFound
	// and no follow-up SELECT is requested.
	if _, _, _, _, err := st.ConsumeAuthCode("hash1", time.Now()); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("reused code: %v, want ErrNotFound", err)
	}
	if err := st.CreateAuthCode("hash2", "q-code", "client1", "https://example.com/cb", "ch", time.Now().Add(-time.Minute)); err != nil {
		t.Fatal(err)
	}
	if _, _, _, _, err := st.ConsumeAuthCode("hash2", time.Now()); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("expired code: %v, want ErrNotFound", err)
	}
	attempts := f.attemptsSnapshot()
	want := []string{insertSQL, updateSQL, selectSQL, updateSQL, insertSQL, updateSQL}
	if len(attempts) != len(want) {
		t.Fatalf("attempts = %v, want %v", attempts, want)
	}
	for i, w := range want {
		if attempts[i] != w {
			t.Fatalf("attempts[%d] = %q, want %q (full: %v)", i, attempts[i], w, attempts)
		}
	}
}

// TestTimestampParamsAreUnixIntegers locks the store.go-compatible binding
// contract: every timestamp parameter is an INTEGER unix-seconds value
// (JSON number), never a string, and expiry filters bind the same epoch the
// SQLite store computes.
func TestTimestampParamsAreUnixIntegers(t *testing.T) {
	exp := time.Now().Add(time.Hour).Truncate(time.Second)
	now := time.Now().Truncate(time.Second)
	createServiceSQL := normSQL(`INSERT INTO services (tenant_slug, name, agent_key_hash, auth_mode, password_hash, created_at)
		SELECT ?, ?, ?, ?, ?, ?
		WHERE EXISTS (SELECT 1 FROM tenants WHERE slug = ?)`)
	st, f := newFake(t, map[string][]rule{
		createTenantSQL:  {{result: canned{written: 1}}},
		createServiceSQL: {{result: canned{written: 1}}},
		normSQL(`INSERT OR IGNORE INTO signing_keys (tenant_slug, private_key_pem, created_at)
			VALUES (?, ?, ?)`): {{result: canned{written: 1}}},
		normSQL(`INSERT INTO oauth_clients (tenant_slug, client_id, redirect_uris, created_at)
			VALUES (?, ?, ?, ?)`): {{result: canned{written: 1}}},
		`INSERT INTO auth_codes (code_hash, tenant_slug, client_id, redirect_uri, code_challenge, expires_at) VALUES (?, ?, ?, ?, ?, ?)`: {
			{result: canned{written: 1}},
		},
		`UPDATE auth_codes SET used_at = ? WHERE code_hash = ? AND used_at IS NULL AND expires_at > ?`: {
			{result: canned{written: 1}},
		},
		`SELECT tenant_slug, client_id, redirect_uri, code_challenge FROM auth_codes WHERE code_hash = ?`: {
			{result: canned{rows: []map[string]any{
				row("tenant_slug", "q-x", "client_id", "c", "redirect_uri", "https://cb", "code_challenge", "ch"),
			}}},
		},
		`SELECT slug FROM tenants WHERE expires_at IS NOT NULL AND expires_at <= ?`: {
			{result: canned{rows: []map[string]any{row("slug", "q-x")}}},
		},
		deleteTenantSQL: {{result: canned{written: 1}}},
		`SELECT COUNT(*) AS n FROM tenants WHERE expires_at IS NOT NULL AND expires_at > ?`: {
			{result: canned{rows: []map[string]any{row("n", 1)}}},
		},
		`DELETE FROM quick_rate WHERE window_start < ?`: {{result: canned{written: 0}}},
		`INSERT INTO quick_rate (ip, window_start, count) VALUES (?, ?, 1) ON CONFLICT (ip, window_start) DO UPDATE SET count = count + 1`: {
			{result: canned{written: 1}},
		},
		`SELECT count FROM quick_rate WHERE ip = ? AND window_start = ?`: {
			{result: canned{rows: []map[string]any{row("count", 1)}}},
		},
	})

	if err := st.CreateTenantExpiry("q-x", "x", &exp); err != nil {
		t.Fatal(err)
	}
	if _, err := st.CreateService("q-x", &store.Service{Name: "mcp"}); err != nil {
		t.Fatal(err)
	}
	if err := st.CreateSigningKey("q-x", "pem"); err != nil {
		t.Fatal(err)
	}
	if err := st.CreateOAuthClient("q-x", "c", `["https://cb"]`); err != nil {
		t.Fatal(err)
	}
	if err := st.CreateAuthCode("h", "q-x", "c", "https://cb", "ch", exp); err != nil {
		t.Fatal(err)
	}
	if _, _, _, _, err := st.ConsumeAuthCode("h", now); err != nil {
		t.Fatal(err)
	}
	if _, err := st.DeleteExpiredTenants(now); err != nil {
		t.Fatal(err)
	}
	if _, err := st.CountLiveTenants(now); err != nil {
		t.Fatal(err)
	}
	if _, err := st.QuickRateHit("203.0.113.1", now); err != nil {
		t.Fatal(err)
	}

	expU, nowU := exp.Unix(), now.Unix()
	// Requests 0-5 are the migrate DDL; each call above added one request
	// per statement, in call order. A nil `want` means the exact value is
	// time.Now()-derived and cannot be predicted — assert integer-typed only.
	checks := []struct {
		req  int    // index into requestsSnapshot
		idx  int    // param index
		want *int64 // expected unix seconds, or nil for "any integer"
	}{
		{6, 2, nil},    // CreateTenantExpiry created_at
		{6, 3, &expU},  // CreateTenantExpiry expires_at
		{7, 5, nil},    // CreateService created_at
		{8, 2, nil},    // CreateSigningKey created_at
		{9, 3, nil},    // CreateOAuthClient created_at
		{10, 5, &expU}, // CreateAuthCode expires_at
		{11, 0, &nowU}, // ConsumeAuthCode used_at
		{11, 2, &nowU}, // ConsumeAuthCode expires_at filter
		{13, 0, &nowU}, // DeleteExpiredTenants now filter
		{15, 0, &nowU}, // CountLiveTenants now filter
		{16, 0, nil},   // QuickRateHit prune window (hour bucket)
		{17, 1, nil},   // QuickRateHit upsert window (hour bucket)
	}
	reqs := f.requestsSnapshot()
	for _, c := range checks {
		p := reqs[c.req].Params[c.idx]
		n, ok := p.(float64)
		if !ok || n != float64(int64(n)) {
			t.Fatalf("request %d (%s) param %d = %v (%T), want integer unix seconds",
				c.req, normSQL(reqs[c.req].SQL), c.idx, p, p)
		}
		if c.want != nil && n != float64(*c.want) {
			t.Fatalf("request %d (%s) param %d = %v, want %d",
				c.req, normSQL(reqs[c.req].SQL), c.idx, n, *c.want)
		}
	}
}

func TestConsumeAuthCodeUpdateFailure(t *testing.T) {
	st, f := newFake(t, map[string][]rule{
		`UPDATE auth_codes SET used_at = ? WHERE code_hash = ? AND used_at IS NULL AND expires_at > ?`: {
			{result: canned{errMsg: "database is locked"}},
		},
	})
	_, _, _, _, err := st.ConsumeAuthCode("hash1", time.Now())
	if err == nil || errors.Is(err, store.ErrNotFound) {
		t.Fatalf("update failure: %v, want a wrapped (non-sentinel) error", err)
	}
	attempts := f.attemptsSnapshot()
	if len(attempts) != 1 {
		t.Fatalf("attempts = %v, want [UPDATE] only (SELECT must not run)", attempts)
	}
}

func TestTopLevelAPIError(t *testing.T) {
	f := &fakeD1{
		rules:   map[string][]rule{},
		httpErr: `{"success":false,"errors":[{"code":400,"message":"Invalid request: missing database ID"}]}`,
	}
	srv := httptest.NewServer(f)
	defer srv.Close()
	old := apiBaseURL
	apiBaseURL = srv.URL
	defer func() { apiBaseURL = old }()

	st, err := New(Config{AccountID: "acc", DatabaseID: "db", APIToken: "tok"})
	if err == nil {
		t.Fatal("New against failing API: want error")
	}
	_ = st
	if !strings.Contains(err.Error(), "Invalid request") {
		t.Fatalf("error = %v, want the API message", err)
	}
}
