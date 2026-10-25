package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/terragohan/mcptunnels/internal/agent"
	"github.com/terragohan/mcptunnels/internal/bridge"
	"github.com/terragohan/mcptunnels/internal/cli"
	"github.com/terragohan/mcptunnels/internal/config"
)

// runExpose implements `mcptunnel expose [--server URL] -- <cmd>...`: it
// creates an anonymous quick tunnel via POST /api/v1/quick, runs the given
// stdio MCP server command behind a local HTTP bridge, and connects the
// tunnel agent — one command from local MCP server to public endpoint,
// ngrok-style.
//
// OAuth is on by default: a random password is generated, sent to tunneld,
// and printed. The OAuth authorize endpoint requires it. --no-auth skips
// both. On Ctrl-C the tunnel is deleted via DELETE /api/v1/quick/{tenant}.
func runExpose(w io.Writer, args []string) error {
	// Everything after "--" is the MCP server command.
	flagArgs, cmdArgs := args, []string(nil)
	for i, a := range args {
		if a == "--" {
			flagArgs, cmdArgs = args[:i], args[i+1:]
			break
		}
	}

	fs := cli.NewFlagSet("expose")
	server := fs.String("server", cli.DefaultServer, "tunneld base URL (defaults to the hosted "+cli.DefaultServer+")")
	configPath := fs.String("config", "", "tunneld.yaml to read the server URL from (same-host use)")
	noAuth := fs.Bool("no-auth", false, "disable OAuth on the public endpoint (anyone with the URL can use it)")
	pos, err := cli.ParseIntermixed(fs, flagArgs)
	if err != nil {
		return cli.Usagef("%v", err)
	}
	if len(pos) > 0 || len(cmdArgs) == 0 {
		return cli.Usagef("usage: mcptunnel expose [--server URL | --config PATH] [--no-auth] -- <mcp server command> [args...]")
	}

	// --config wins only when --server was left at the hosted default.
	base := *server
	if base == cli.DefaultServer && *configPath != "" {
		s, err := cli.ServerFromConfig(*configPath)
		if err != nil {
			return err
		}
		base = s
	}

	auth := !*noAuth

	// Generate the authorize password when OAuth is on.
	var password string
	if auth {
		b := make([]byte, 12)
		rand.Read(b)
		password = hex.EncodeToString(b)
	}

	// Create the anonymous quick tunnel: an ephemeral tenant (24h TTL) with a
	// single service; the agent key authenticates the agent below.
	c := cli.NewClient(base)
	var resp struct {
		Tenant    string `json:"tenant"`
		Service   string `json:"service"`
		AgentKey  string `json:"agent_key"`
		ExpiresAt int64  `json:"expires_at"`
	}
	if err := c.Do("POST", "/quick", nil, map[string]any{
		"auth":     auth,
		"password": password,
	}, &resp); err != nil {
		return err
	}
	ttl := time.Until(time.Unix(resp.ExpiresAt, 0)).Round(time.Minute)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// Spawn the MCP server and bridge it to a loopback HTTP endpoint.
	b, err := bridge.Start(ctx, cmdArgs[0], cmdArgs[1:]...)
	if err != nil {
		return fmt.Errorf("starting mcp server: %w", err)
	}
	defer b.Close()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return err
	}
	defer ln.Close()
	httpSrv := &http.Server{Handler: b}
	go httpSrv.Serve(ln)
	defer httpSrv.Close()

	cfg := &config.AgentConfig{
		Server:   httpToWS(base),
		Tenant:   resp.Tenant,
		Service:  resp.Service,
		AgentKey: resp.AgentKey,
		Upstream: "http://" + ln.Addr().String(),
	}
	cfg.Reconnect.InitialBackoff = config.Duration(time.Second)
	cfg.Reconnect.MaxBackoff = config.Duration(30 * time.Second)

	agentClient, err := agent.New(cfg)
	if err != nil {
		return err
	}

	publicURL := fmt.Sprintf("%s/t/%s/s/%s", base, resp.Tenant, resp.Service)
	if auth {
		fmt.Fprintf(w, "\ntemporary public MCP endpoint (expires in %s, OAuth-protected):\n\n  %s\n\n  password: %s\n\nClients discover OAuth automatically. Press Ctrl-C to stop.\n",
			ttl, publicURL, password)
	} else {
		fmt.Fprintf(w, "\ntemporary public MCP endpoint (expires in %s):\n\n  %s\n\nno signup needed — anyone with this URL can use the server. Press Ctrl-C to stop.\n",
			ttl, publicURL)
	}

	// Delete the tunnel on exit so the password stops working.
	defer deleteTunnel(base, resp.Tenant, resp.Service, resp.AgentKey)

	agentErr := make(chan error, 1)
	go func() { agentErr <- agentClient.Run(ctx) }()

	select {
	case err := <-agentErr:
		if ctx.Err() != nil {
			return nil // interrupted by the user
		}
		return err
	case <-b.Done():
		return fmt.Errorf("mcp server exited: %w", b.Err())
	}
}

// deleteTunnel calls DELETE /api/v1/quick/{tenant} to destroy the tunnel.
// Best-effort: failures are silently ignored (the 24h janitor is the safety
// net).
func deleteTunnel(base, tenant, service, agentKey string) {
	req, err := http.NewRequest("DELETE",
		fmt.Sprintf("%s/api/v1/quick/%s", strings.TrimRight(base, "/"), tenant), nil)
	if err != nil {
		return
	}
	req.Header.Set("Authorization", "Bearer "+agentKey)
	req.Header.Set("X-Service-Name", service)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return
	}
	resp.Body.Close()
}

// httpToWS converts an http(s) base URL to the ws(s) URL the agent dials.
func httpToWS(base string) string {
	switch {
	case strings.HasPrefix(base, "https://"):
		return "wss://" + strings.TrimPrefix(base, "https://")
	case strings.HasPrefix(base, "http://"):
		return "ws://" + strings.TrimPrefix(base, "http://")
	default:
		return base // already ws:// or wss://
	}
}
