package proxy_test

import (
	"bufio"
	"context"
	"encoding/json"
	"net"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/terragohan/mcptunnels/internal/agent"
	"github.com/terragohan/mcptunnels/internal/bridge"
	"github.com/terragohan/mcptunnels/internal/config"
	"github.com/terragohan/mcptunnels/internal/server"
	"github.com/terragohan/mcptunnels/internal/store/storetest"
)

// TestFakeMCPChild is not a test: it is the fake stdio MCP server child
// process, re-execed by bridge.Start as
//
//	bridge.Start(ctx, os.Args[0], "-test.run=TestFakeMCPChild")
//
// with MCPTUNNELS_FAKE_CHILD=1 in the environment. It answers initialize and
// tools/list with canned results and, right after initialize, emits one
// server-initiated notification so the SSE stream has something to carry.
// Without the env var it returns immediately so the real test run skips it.
func TestFakeMCPChild(t *testing.T) {
	if os.Getenv("MCPTUNNELS_FAKE_CHILD") != "1" {
		return
	}
	dec := json.NewDecoder(os.Stdin)
	enc := json.NewEncoder(os.Stdout)
	for {
		var req struct {
			ID     any    `json:"id"`
			Method string `json:"method"`
		}
		if err := dec.Decode(&req); err != nil {
			os.Exit(0) // stdin closed: bridge is shutting us down
		}
		switch req.Method {
		case "initialize":
			enc.Encode(map[string]any{ //nolint:errcheck // stdout closes on shutdown
				"jsonrpc": "2.0", "id": req.ID,
				"result": map[string]any{
					"protocolVersion": "2024-11-05",
					"capabilities":    map[string]any{},
					"serverInfo":      map[string]any{"name": "fake-mcp", "version": "0.0.0"},
				},
			})
			// One server-initiated notification for the SSE stream.
			enc.Encode(map[string]any{ //nolint:errcheck
				"jsonrpc": "2.0", "method": "notifications/tools/list_changed",
			})
		case "tools/list":
			enc.Encode(map[string]any{ //nolint:errcheck
				"jsonrpc": "2.0", "id": req.ID,
				"result": map[string]any{
					"tools": []any{map[string]any{
						"name": "fake_tool", "description": "canned tool",
					}},
				},
			})
		default:
			if req.ID != nil {
				enc.Encode(map[string]any{"jsonrpc": "2.0", "id": req.ID, "result": nil}) //nolint:errcheck
			}
		}
	}
}

// TestStdioTunnelEndToEnd covers `mcptunnel expose --no-auth -- <cmd>`: the
// full tunneld handler (server.NewHandler, not a partial mux), a quick tunnel
// with auth disabled, and a local stdio MCP server behind the loopback
// bridge — wired exactly like cmd/mcptunnel/expose.go. Over the public URL
// it asserts the streamable-HTTP surface: POST initialize returns a session
// id, POST tools/list returns the canned tool list, and GET with
// Accept: text/event-stream streams the child's server-initiated
// notification.
func TestStdioTunnelEndToEnd(t *testing.T) {
	st := storetest.Open(t)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	base := "http://" + ln.Addr().String()
	handler, gw := server.NewHandler(st, base)
	go http.Serve(ln, handler) //nolint:errcheck // test teardown closes ln
	t.Cleanup(func() { ln.Close() })

	// --no-auth: an open quick tunnel.
	resp, err := http.Post(base+"/api/v1/quick", "application/json",
		strings.NewReader(`{"auth": false}`))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("quick: status %d, want 201", resp.StatusCode)
	}
	var qr struct {
		Tenant    string `json:"tenant"`
		Service   string `json:"service"`
		AgentKey  string `json:"agent_key"`
		ExpiresAt int64  `json:"expires_at"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&qr); err != nil {
		t.Fatal(err)
	}

	// Local stdio MCP server behind the loopback bridge, as runExpose does.
	t.Setenv("MCPTUNNELS_FAKE_CHILD", "1")
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	b, err := bridge.Start(ctx, os.Args[0], "-test.run=TestFakeMCPChild")
	if err != nil {
		t.Fatalf("bridge.Start: %v", err)
	}
	t.Cleanup(b.Close)
	upLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	httpSrv := &http.Server{Handler: b}
	go httpSrv.Serve(upLn) //nolint:errcheck // test teardown closes the server
	t.Cleanup(func() { httpSrv.Close() })

	cfg := &config.AgentConfig{
		Server:   "ws://" + ln.Addr().String(),
		Tenant:   qr.Tenant,
		AgentKey: qr.AgentKey,
		Service:  qr.Service,
		Upstream: "http://" + upLn.Addr().String(),
	}
	cfg.Reconnect.InitialBackoff = config.Duration(10 * time.Millisecond)
	cfg.Reconnect.MaxBackoff = config.Duration(200 * time.Millisecond)
	c, err := agent.New(cfg)
	if err != nil {
		t.Fatalf("agent.New: %v", err)
	}
	go c.Run(ctx) //nolint:errcheck // test teardown cancels ctx

	waitForProxy(t, func() bool { return gw.Online(qr.Tenant, qr.Service) },
		"agent did not connect within 5s")

	public := base + "/t/" + qr.Tenant + "/s/" + qr.Service

	t.Run("initialize", func(t *testing.T) {
		resp := postMCP(t, public, `{"jsonrpc":"2.0","id":1,"method":"initialize"}`)
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("status %d, want 200", resp.StatusCode)
		}
		if sid := resp.Header.Get("Mcp-Session-Id"); sid == "" {
			t.Fatal("missing Mcp-Session-Id header")
		}
		var body struct {
			Result struct {
				ProtocolVersion string `json:"protocolVersion"`
			} `json:"result"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
			t.Fatal(err)
		}
		if body.Result.ProtocolVersion != "2024-11-05" {
			t.Fatalf("protocolVersion = %q, want 2024-11-05", body.Result.ProtocolVersion)
		}
	})

	t.Run("tools list", func(t *testing.T) {
		resp := postMCP(t, public, `{"jsonrpc":"2.0","id":2,"method":"tools/list"}`)
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("status %d, want 200", resp.StatusCode)
		}
		var body struct {
			Result struct {
				Tools []struct {
					Name string `json:"name"`
				} `json:"tools"`
			} `json:"result"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
			t.Fatal(err)
		}
		if len(body.Result.Tools) != 1 || body.Result.Tools[0].Name != "fake_tool" {
			t.Fatalf("tools = %+v, want the canned fake_tool", body.Result.Tools)
		}
	})

	t.Run("sse notification", func(t *testing.T) {
		req, err := http.NewRequest(http.MethodGet, public, nil)
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Accept", "text/event-stream")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("status %d, want 200", resp.StatusCode)
		}
		if ct := resp.Header.Get("Content-Type"); ct != "text/event-stream" {
			t.Fatalf("content-type = %q, want text/event-stream", ct)
		}

		dataCh := make(chan string, 16)
		go func() {
			sc := bufio.NewScanner(resp.Body)
			for sc.Scan() {
				if line := sc.Text(); strings.HasPrefix(line, "data: ") {
					dataCh <- strings.TrimPrefix(line, "data: ")
				}
			}
		}()
		select {
		case data := <-dataCh:
			if !strings.Contains(data, "notifications/tools/list_changed") {
				t.Fatalf("SSE data = %q, want notifications/tools/list_changed", data)
			}
		case <-time.After(5 * time.Second):
			t.Fatal("no SSE notification within 5s")
		}
	})
}

func postMCP(t *testing.T, url, body string) *http.Response {
	t.Helper()
	resp, err := http.Post(url, "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	return resp
}

func waitForProxy(t *testing.T, cond func() bool, msg string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatal(msg)
		}
		time.Sleep(10 * time.Millisecond)
	}
}
