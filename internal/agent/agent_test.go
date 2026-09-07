package agent

import (
	"bufio"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/terragohan/mcptunnels/internal/config"
	"github.com/terragohan/mcptunnels/internal/tokencache"
)

// TestHandleStreamHeaderPolicy drives handleStream over a net.Pipe with a
// request that carries the public tunnel host and client credentials, and
// asserts what the upstream actually sees.
func TestHandleStreamHeaderPolicy(t *testing.T) {
	var gotHeader http.Header
	var gotHost string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotHeader = r.Header.Clone()
		gotHost = r.Host
		body, _ := io.ReadAll(r.Body)
		w.Header().Set("X-Upstream", "seen")
		w.Write(body) // echo the body back
	}))
	defer srv.Close()

	c, err := New(&config.AgentConfig{
		Server:          "wss://tunnel.example.com",
		Tenant:          "tenant",
		Service:         "svc",
		AgentKey:        "key",
		Upstream:        srv.URL + "/mcp",
		UpstreamHeaders: map[string][]string{"Authorization": {"Bearer owner-key"}, "X-Owner": {"yes"}},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	client, server := net.Pipe()
	go c.handleStream(server)

	req, err := http.NewRequest("POST", "http://public.example.com/t/tenant/s/svc/mcp", strings.NewReader("hello"))
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	req.Header.Set("Authorization", "Bearer client-jwt")
	req.Header.Set("Proxy-Authorization", "Basic eW91")
	req.Header.Set("Cookie", "session=abc")
	req.Header.Set("X-Echo", "keep")
	req.Header.Set("Mcp-Session-Id", "sess-1")
	if err := req.Write(client); err != nil {
		t.Fatalf("request write: %v", err)
	}

	resp, err := http.ReadResponse(bufio.NewReader(client), req)
	if err != nil {
		t.Fatalf("ReadResponse: %v", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil || string(body) != "hello" {
		t.Fatalf("body round-trip = %q, %v; want %q", body, err, "hello")
	}

	// Client credentials never reach the upstream. Authorization is present,
	// but it must be the injected owner key, not the client's JWT.
	for _, h := range []string{"Proxy-Authorization", "Cookie"} {
		if gotHeader.Get(h) == "" {
			continue
		}
		t.Errorf("client header %s leaked upstream: %q", h, gotHeader.Get(h))
	}
	// Owner credentials and unrelated headers do.
	if got := gotHeader.Get("Authorization"); got != "Bearer owner-key" {
		t.Errorf("Authorization = %q; want injected owner key (client JWT must be stripped)", got)
	}
	if got := gotHeader.Get("X-Owner"); got != "yes" {
		t.Errorf("X-Owner = %q; want yes", got)
	}
	if got := gotHeader.Get("X-Echo"); got != "keep" {
		t.Errorf("X-Echo = %q; want keep", got)
	}
	// MCP session ids pass through for remote-upstream session semantics.
	if got := gotHeader.Get("Mcp-Session-Id"); got != "sess-1" {
		t.Errorf("Mcp-Session-Id = %q; want sess-1", got)
	}
	// The upstream sees its own host, not the public tunnel host.
	if want := mustHost(t, srv.URL); gotHost != want {
		t.Errorf("Host = %q; want %q", gotHost, want)
	}
}

// TestTransportInjectsRegistryToken wires a tokencache.Transport via
// cfg.Transport and asserts the registry token reaches the upstream after
// the client's Authorization has been stripped.
func TestTransportInjectsRegistryToken(t *testing.T) {
	var gotAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		w.Write([]byte("ok"))
	}))
	defer srv.Close()

	store := &tokencache.Store{Dir: t.TempDir()}
	e := &tokencache.Entry{URL: srv.URL + "/mcp", AccessToken: "registry-key"}
	if err := store.Save(e); err != nil {
		t.Fatal(err)
	}

	c, err := New(&config.AgentConfig{
		Server:    "wss://tunnel.example.com",
		Tenant:    "tenant",
		Service:   "svc",
		AgentKey:  "key",
		Upstream:  srv.URL + "/mcp",
		Transport: &tokencache.Transport{Source: tokencache.NewSource(store, e)},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	client, server := net.Pipe()
	go c.handleStream(server)

	req, err := http.NewRequest("POST", "http://public.example.com/t/tenant/s/svc/mcp", strings.NewReader("hello"))
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	req.Header.Set("Authorization", "Bearer client-jwt")
	if err := req.Write(client); err != nil {
		t.Fatalf("request write: %v", err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(client), req)
	if err != nil {
		t.Fatalf("ReadResponse: %v", err)
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)

	if gotAuth != "Bearer registry-key" {
		t.Errorf("Authorization = %q; want the registry token (client JWT stripped first)", gotAuth)
	}
}

func TestNewRejectsBadUpstream(t *testing.T) {
	for _, u := range []string{"/mcp", "example.com/mcp", "ftp://example.com"} {
		if _, err := New(&config.AgentConfig{Upstream: u}); err == nil {
			t.Errorf("New(%q): want error, got nil", u)
		}
	}
}

func mustHost(t *testing.T, raw string) string {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("url.Parse(%q): %v", raw, err)
	}
	return u.Host
}
