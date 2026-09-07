package tokencache

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func testStore(t *testing.T) *Store {
	t.Helper()
	return &Store{Dir: t.TempDir()}
}

func TestStoreRoundTrip(t *testing.T) {
	s := testStore(t)
	e := &Entry{
		URL:          "https://api.example.com/mcp",
		AccessToken:  "tok-abc",
		ExpiresAt:    1757188800,
		RefreshToken: "ref-1",
		TokenURL:     "https://auth.example.com/token",
		ClientID:     "client-1",
	}
	if err := s.Save(e); err != nil {
		t.Fatal(err)
	}
	// File perms 0600.
	fis, err := os.ReadDir(s.Dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(fis) != 1 {
		t.Fatalf("want 1 file, got %d", len(fis))
	}
	fi, _ := fis[0].Info()
	if fi.Mode().Perm() != 0600 {
		t.Fatalf("file perms = %o, want 0600", fi.Mode().Perm())
	}
	got, err := s.Lookup(e.URL)
	if err != nil {
		t.Fatal(err)
	}
	if *got != *e {
		t.Fatalf("round trip mismatch: %+v != %+v", got, e)
	}
	// URL-key stability: normalization variants hit the same entry.
	for _, raw := range []string{"https://API.example.COM:443/mcp/", "https://api.example.com/mcp"} {
		got, err := s.Lookup(raw)
		if err != nil || got == nil {
			t.Fatalf("lookup %q: %v, %v", raw, got, err)
		}
	}
	if absent, err := s.Lookup("https://other.example.com/mcp"); err != nil || absent != nil {
		t.Fatalf("absent lookup = %v, %v", absent, err)
	}
	if err := s.Remove(e.URL); err != nil {
		t.Fatal(err)
	}
	if absent, _ := s.Lookup(e.URL); absent != nil {
		t.Fatal("entry still present after Remove")
	}
	if err := s.Remove(e.URL); err != nil {
		t.Fatalf("removing absent entry: %v", err)
	}
}

func TestStaticToken(t *testing.T) {
	src := NewSource(testStore(t), &Entry{URL: "https://x.example.com", AccessToken: "tok-static"})
	tok, err := src.Token(context.Background())
	if err != nil || tok != "tok-static" {
		t.Fatalf("got %q, %v", tok, err)
	}
	// Expired with no refresh path → error pointing at token add.
	src.Entry.ExpiresAt = time.Now().Unix() - 60
	if _, err := src.Token(context.Background()); err == nil ||
		!strings.Contains(err.Error(), "token add") {
		t.Fatalf("expired static token: err = %v", err)
	}
}

func TestRefreshGrant(t *testing.T) {
	var gotForm string
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		gotForm = string(body)
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"access_token":"tok-new","expires_in":3600,"refresh_token":"ref-rotated"}`)
	}))
	defer ts.Close()

	s := testStore(t)
	e := &Entry{
		URL:          "https://api.example.com/mcp",
		AccessToken:  "tok-old",
		ExpiresAt:    time.Now().Unix() - 60, // expired
		RefreshToken: "ref-1",
		TokenURL:     ts.URL,
		ClientID:     "client-1",
	}
	if err := s.Save(e); err != nil {
		t.Fatal(err)
	}
	src := NewSource(s, e)
	tok, err := src.Token(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if tok != "tok-new" {
		t.Fatalf("token = %q", tok)
	}
	if !strings.Contains(gotForm, "grant_type=refresh_token") ||
		!strings.Contains(gotForm, "refresh_token=ref-1") ||
		!strings.Contains(gotForm, "client_id=client-1") {
		t.Fatalf("refresh request form = %q", gotForm)
	}
	// Entry file rewritten with the rotated tokens.
	back, err := s.Lookup(e.URL)
	if err != nil {
		t.Fatal(err)
	}
	if back.AccessToken != "tok-new" || back.RefreshToken != "ref-rotated" || back.ExpiresAt == 0 {
		t.Fatalf("rewritten entry = %+v", back)
	}
}

func TestTokenCmd(t *testing.T) {
	src := NewSource(testStore(t), &Entry{
		URL:      "https://x.example.com",
		TokenCmd: "printf tok-123",
	})
	tok, err := src.Token(context.Background())
	if err != nil || tok != "tok-123" {
		t.Fatalf("got %q, %v", tok, err)
	}
	// Failure propagates.
	src.Entry.TokenCmd = "exit 1"
	if _, err := src.Refresh(context.Background()); err == nil {
		t.Fatal("expected error from failing token command")
	}
	// Empty output is an error too.
	src.Entry.TokenCmd = "true"
	if _, err := src.Refresh(context.Background()); err == nil {
		t.Fatal("expected error from empty token command output")
	}
}

func TestConcurrentRefreshCollapses(t *testing.T) {
	var calls atomic.Int32
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		fmt.Fprint(w, `{"access_token":"tok-new","expires_in":3600}`)
	}))
	defer ts.Close()

	src := NewSource(testStore(t), &Entry{
		URL:          "https://api.example.com/mcp",
		AccessToken:  "tok-old",
		ExpiresAt:    time.Now().Unix() - 60,
		RefreshToken: "ref-1",
		TokenURL:     ts.URL,
	})
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			tok, err := src.Token(context.Background())
			if err != nil || tok != "tok-new" {
				t.Errorf("got %q, %v", tok, err)
			}
		}()
	}
	wg.Wait()
	if n := calls.Load(); n != 1 {
		t.Fatalf("refresh calls = %d, want 1", n)
	}
}

func TestTransport401Retry(t *testing.T) {
	var (
		mu      sync.Mutex
		current = "tok-A"
		auths   []string
		failed  bool
	)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		auths = append(auths, r.Header.Get("Authorization"))
		want := "Bearer " + current
		ok := r.Header.Get("Authorization") == want
		if ok && !failed {
			// Valid token A still gets one 401, forcing a refresh to B.
			failed = true
			current = "tok-B"
			ok = false
		}
		mu.Unlock()
		if !ok {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		fmt.Fprint(w, "ok")
	}))
	defer upstream.Close()

	src := NewSource(testStore(t), &Entry{
		URL:         upstream.URL,
		AccessToken: "tok-A",
		TokenCmd:    "printf tok-B",
	})
	tr := &Transport{Source: src}

	req, _ := http.NewRequest(http.MethodPost, upstream.URL+"/mcp",
		strings.NewReader(`{"jsonrpc":"2.0"}`))
	resp, err := tr.RoundTrip(req)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 || string(body) != "ok" {
		t.Fatalf("retry response = %s %q", resp.Status, body)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(auths) != 2 || auths[1] != "Bearer tok-B" {
		t.Fatalf("auth headers seen = %v", auths)
	}
}

func TestTransportPassesThroughSecond401(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer upstream.Close()

	src := NewSource(testStore(t), &Entry{
		URL:         upstream.URL,
		AccessToken: "tok-A",
		TokenCmd:    "printf tok-B",
	})
	tr := &Transport{Source: src}
	req, _ := http.NewRequest(http.MethodGet, upstream.URL, nil)
	resp, err := tr.RoundTrip(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("second 401 not passed through: %s", resp.Status)
	}
}

func TestDefaultStoreUsesUserConfigDir(t *testing.T) {
	// The default store keys off os.UserConfigDir; just sanity-check the
	// path shape on this platform.
	s := DefaultStore()
	d, err := s.dir()
	if err != nil {
		t.Skip(err)
	}
	if !strings.HasSuffix(filepath.ToSlash(d), "mcptunnels/tokens") {
		t.Fatalf("default dir = %q", d)
	}
}
