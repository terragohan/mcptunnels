package server_test

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/terragohan/mcptunnels/internal/server"
	"github.com/terragohan/mcptunnels/internal/store/storetest"
)

// TestRobotsTxtDisallowsAll: the relay's only public URL space is ephemeral
// tenant endpoints, which must never be indexed — /robots.txt must disallow
// everything for every crawler.
func TestRobotsTxtDisallowsAll(t *testing.T) {
	st := storetest.Open(t)
	handler, _ := server.NewHandler(st, "http://example.com")

	req := httptest.NewRequest(http.MethodGet, "/robots.txt", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	resp := rec.Result()
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); !strings.HasPrefix(ct, "text/plain") {
		t.Fatalf("Content-Type = %q, want text/plain", ct)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(body), "User-agent: *") || !strings.Contains(string(body), "Disallow: /") {
		t.Fatalf("robots.txt body %q missing expected directives", body)
	}
}
