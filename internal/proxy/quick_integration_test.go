package proxy_test

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/terragohan/mcptunnels/internal/agent"
	"github.com/terragohan/mcptunnels/internal/config"
	"github.com/terragohan/mcptunnels/internal/controlplane"
	"github.com/terragohan/mcptunnels/internal/gateway"
	"github.com/terragohan/mcptunnels/internal/proxy"
	"github.com/terragohan/mcptunnels/internal/store/storetest"
	"github.com/terragohan/mcptunnels/internal/tunnelproto"
)

// TestQuickTunnelEndToEnd drives the whole product flow in-process, exactly
// as `mcptunnel expose` does: POST /api/v1/quick creates the ephemeral tenant
// and returns an agent key, an agent connects with that key, and an
// unauthenticated tools/call request flows public proxy → agent websocket →
// upstream.
func TestQuickTunnelEndToEnd(t *testing.T) {
	// Dummy upstream MCP-ish HTTP endpoint: echoes the path and body.
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		fmt.Fprintf(w, "path=%s body=%s", r.URL.Path, body)
	}))
	defer upstream.Close()

	st := storetest.Open(t)
	gw := gateway.New(st)
	mux := http.NewServeMux()
	mux.Handle(tunnelproto.ConnectPath, gw)
	mux.Handle("/api/v1/", controlplane.New(st).Handler())
	mux.Handle("/t/{tenant}/s/", proxy.New(gw, st, nil))
	tunneld := httptest.NewServer(mux)
	defer tunneld.Close()

	// Create the quick tunnel (what `mcptunnel expose` does first).
	resp, err := http.Post(tunneld.URL+"/api/v1/quick", "application/json",
		strings.NewReader(`{"auth":false}`))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("quick: status %d, want 201", resp.StatusCode)
	}
	var quick struct {
		Tenant   string `json:"tenant"`
		Service  string `json:"service"`
		AgentKey string `json:"agent_key"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&quick); err != nil {
		t.Fatal(err)
	}

	// Connect the agent with the returned key.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	agentCfg := &config.AgentConfig{
		Server:   "ws://" + tunneld.Listener.Addr().String(),
		Tenant:   quick.Tenant,
		Service:  quick.Service,
		AgentKey: quick.AgentKey,
		Upstream: upstream.URL,
	}
	agentCfg.Reconnect.InitialBackoff = config.Duration(10 * time.Millisecond)
	agentCfg.Reconnect.MaxBackoff = config.Duration(200 * time.Millisecond)
	client, err := agent.New(agentCfg)
	if err != nil {
		t.Fatalf("agent.New: %v", err)
	}
	go client.Run(ctx) //nolint:errcheck // test teardown cancels ctx

	deadline := time.Now().Add(5 * time.Second)
	for !gw.Online(quick.Tenant, quick.Service) {
		if time.Now().After(deadline) {
			t.Fatal("agent did not connect within 5s")
		}
		time.Sleep(10 * time.Millisecond)
	}

	// Unauthenticated tools/call through the public URL.
	url := fmt.Sprintf("%s/t/%s/s/%s/mcp", tunneld.URL, quick.Tenant, quick.Service)
	rpc := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"x"}}`
	resp2, err := http.Post(url, "application/json", strings.NewReader(rpc))
	if err != nil {
		t.Fatal(err)
	}
	defer resp2.Body.Close()
	body, _ := io.ReadAll(resp2.Body)
	if resp2.StatusCode != http.StatusOK || !strings.Contains(string(body), "path=/mcp") || !strings.Contains(string(body), "tools/call") {
		t.Fatalf("tools/call: status %d body %q, want 200 through the tunnel", resp2.StatusCode, body)
	}

	// Unknown tenant/service 404; an existing service without an agent 502s.
	for _, u := range []string{
		tunneld.URL + "/t/q-nope/s/mcp/mcp",
		fmt.Sprintf("%s/t/%s/s/nope/mcp", tunneld.URL, quick.Tenant),
	} {
		resp, err := http.Get(u)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusNotFound {
			t.Fatalf("GET %s: status %d, want 404", u, resp.StatusCode)
		}
	}
}
