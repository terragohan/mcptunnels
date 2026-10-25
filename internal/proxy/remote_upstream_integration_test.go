package proxy_test

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/terragohan/mcptunnels/internal/agent"
	"github.com/terragohan/mcptunnels/internal/config"
	"github.com/terragohan/mcptunnels/internal/gateway"
	"github.com/terragohan/mcptunnels/internal/proxy"
	"github.com/terragohan/mcptunnels/internal/store"
	"github.com/terragohan/mcptunnels/internal/store/storetest"
	"github.com/terragohan/mcptunnels/internal/tunnelproto"
)

// TestRemoteUpstreamEndToEnd covers `mcptunnel expose --url <remote MCP
// server> --header ...`: the agent forwards to a remote HTTP upstream, the
// client's credential headers are stripped, and owner-configured headers are
// injected. This is the same path the manual smoke test exercises with real
// binaries, run in-process.
func TestRemoteUpstreamEndToEnd(t *testing.T) {
	// Remote HTTP MCP server: records what it saw, MCP-style base path /mcp.
	type seen struct {
		Method  string `json:"method"`
		Path    string `json:"path"`
		Host    string `json:"host"`
		Auth    string `json:"authorization"`
		Cookie  string `json:"cookie"`
		Owner   string `json:"x-owner"`
		Session string `json:"mcp-session-id"`
	}
	seenCh := make(chan seen, 16)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seenCh <- seen{
			Method:  r.Method,
			Path:    r.URL.Path,
			Host:    r.Host,
			Auth:    r.Header.Get("Authorization"),
			Cookie:  r.Header.Get("Cookie"),
			Owner:   r.Header.Get("X-Owner"),
			Session: r.Header.Get("Mcp-Session-Id"),
		}
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"jsonrpc":"2.0","id":1,"result":{"tools":[]}}`)
	}))
	defer upstream.Close()
	upstreamURL, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatal(err)
	}

	st := storetest.Open(t)
	if err := st.CreateTenant("acme", ""); err != nil {
		t.Fatal(err)
	}
	agentKey, err := st.CreateService("acme", &store.Service{Name: "remote"})
	if err != nil {
		t.Fatal(err)
	}

	gw := gateway.New(st)
	mux := http.NewServeMux()
	mux.Handle(tunnelproto.ConnectPath, gw)
	mux.Handle("/t/{tenant}/s/", proxy.New(gw, st, nil))
	tunneld := httptest.NewServer(mux)
	defer tunneld.Close()

	// Agent as `mcptunnel expose --url <upstream>/mcp --header ...` builds it:
	// remote upstream, owner credentials injected after stripping.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	agentCfg := &config.AgentConfig{
		Server:   "ws://" + tunneld.Listener.Addr().String(),
		Tenant:   "acme",
		AgentKey: agentKey,
		Service:  "remote",
		Upstream: upstream.URL + "/mcp",
		UpstreamHeaders: map[string][]string{
			"Authorization": {"Bearer owner-key"},
			"X-Owner":       {"yes"},
		},
	}
	agentCfg.Reconnect.InitialBackoff = config.Duration(10 * time.Millisecond)
	agentCfg.Reconnect.MaxBackoff = config.Duration(200 * time.Millisecond)
	client, err := agent.New(agentCfg)
	if err != nil {
		t.Fatalf("agent.New: %v", err)
	}
	go client.Run(ctx) //nolint:errcheck // test teardown cancels ctx

	deadline := time.Now().Add(5 * time.Second)
	for !gw.Online("acme", "remote") {
		if time.Now().After(deadline) {
			t.Fatal("agent did not connect within 5s")
		}
		time.Sleep(10 * time.Millisecond)
	}

	// Public client talks to the tunnel URL. It is hostile on purpose:
	// credentials that must never reach the third-party upstream.
	req, err := http.NewRequest(http.MethodPost,
		tunneld.URL+"/t/acme/s/remote/mcp",
		nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer client-jwt")
	req.Header.Set("Cookie", "session=xyz")
	req.Header.Set("Mcp-Session-Id", "sess-1")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("got %d, want 200", resp.StatusCode)
	}
	var rpc struct {
		Result struct {
			Tools []any `json:"tools"`
		} `json:"result"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&rpc); err != nil {
		t.Fatalf("response is not the upstream's JSON-RPC: %v", err)
	}

	select {
	case got := <-seenCh:
		if got.Method != http.MethodPost || got.Path != "/mcp" {
			t.Errorf("upstream saw %s %s; want POST /mcp", got.Method, got.Path)
		}
		if got.Host != upstreamURL.Host {
			t.Errorf("upstream Host = %q; want its own host %q", got.Host, upstreamURL.Host)
		}
		if got.Auth != "Bearer owner-key" {
			t.Errorf("upstream Authorization = %q; want injected owner key", got.Auth)
		}
		if got.Cookie != "" {
			t.Errorf("client Cookie leaked upstream: %q", got.Cookie)
		}
		if got.Owner != "yes" {
			t.Errorf("upstream X-Owner = %q; want yes", got.Owner)
		}
		if got.Session != "sess-1" {
			t.Errorf("Mcp-Session-Id = %q; want sess-1 (session passthrough)", got.Session)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("upstream saw no request")
	}
}
