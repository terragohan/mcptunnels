package proxy_test

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/terragohan/mcptunnels/internal/proxy"
	"github.com/terragohan/mcptunnels/internal/store/storetest"
)

// TestRequestBodyTooLarge verifies the proxy rejects a request whose
// Content-Length exceeds the 8 MiB cap with 413, before touching the store
// or dialing the tunnel (the dialer is nil and never reached).
func TestRequestBodyTooLarge(t *testing.T) {
	st := storetest.Open(t)
	srv := httptest.NewServer(proxy.New(nil, st, nil))
	defer srv.Close()

	// strings.Reader gives the client a known ContentLength: 8 MiB + 1.
	body := strings.NewReader(strings.Repeat("x", 8<<20+1))
	resp, err := http.Post(srv.URL+"/t/q-any/s/mcp/mcp", "application/octet-stream", body)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusRequestEntityTooLarge {
		t.Fatalf("oversized body: status %d, want 413", resp.StatusCode)
	}
}
