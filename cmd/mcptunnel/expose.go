package main

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/generalpiston/openai-tunnel-oauth/internal/agent"
	"github.com/generalpiston/openai-tunnel-oauth/internal/bridge"
	"github.com/generalpiston/openai-tunnel-oauth/internal/cli"
	"github.com/generalpiston/openai-tunnel-oauth/internal/config"
)

// runExpose implements `mcptunnel expose [--server URL] -- <cmd>...`: it
// creates an anonymous quick tunnel via POST /api/v1/quick, runs the given
// stdio MCP server command behind a local HTTP bridge, and connects the
// tunnel agent — one command from local MCP server to public endpoint,
// ngrok-style.
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
	server := fs.String("server", "", "tunneld base URL (required unless --config is given)")
	configPath := fs.String("config", "", "tunneld.yaml to read the server URL from (same-host use)")
	pos, err := cli.ParseIntermixed(fs, flagArgs)
	if err != nil {
		return cli.Usagef("%v", err)
	}
	if len(pos) > 0 || len(cmdArgs) == 0 {
		return cli.Usagef("usage: mcptunnel expose [--server URL | --config PATH] -- <mcp server command> [args...]")
	}

	base := *server
	if base == "" && *configPath != "" {
		s, err := cli.ServerFromConfig(*configPath)
		if err != nil {
			return err
		}
		base = s
	}
	if base == "" {
		return cli.Usagef("usage: mcptunnel expose --server URL -- <mcp server command> [args...]")
	}

	// Create the anonymous quick tunnel: an ephemeral tenant (24h TTL) with a
	// single open service; the agent key authenticates the agent below.
	c := cli.NewClient(base)
	var resp struct {
		Tenant    string `json:"tenant"`
		Service   string `json:"service"`
		AgentKey  string `json:"agent_key"`
		ExpiresAt int64  `json:"expires_at"`
	}
	if err := c.Do("POST", "/quick", nil, nil, &resp); err != nil {
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

	fmt.Fprintf(w, "\ntemporary public MCP endpoint (expires in %s):\n\n  %s/t/%s/s/%s/mcp\n\nno signup needed — anyone with this URL can use the server. Press Ctrl-C to stop.\n",
		ttl, base, resp.Tenant, resp.Service)

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
