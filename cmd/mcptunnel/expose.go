package main

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
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

// runExpose implements `mcptunnel expose <tenant>/<name> [flags] -- <cmd>...`:
// it creates the service if needed, issues a fresh agent key, runs the given
// stdio MCP server command behind a local HTTP bridge, and connects the tunnel
// agent — one command from local MCP server to public endpoint, ngrok-style.
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
	var conn cli.ConnFlags
	conn.Register(fs)
	authMode := fs.String("auth-mode", "strict", "strict|discovery_open")
	pos, err := cli.ParseIntermixed(fs, flagArgs)
	if err != nil {
		return cli.Usagef("%v", err)
	}
	if len(pos) != 1 || len(cmdArgs) == 0 {
		return cli.Usagef("usage: mcptunnel expose <tenant>/<name> [--auth-mode strict|discovery_open] -- <mcp server command> [args...]")
	}
	tenant, name, err := cli.SplitRef(pos[0])
	if err != nil {
		return cli.Usagef("%v", err)
	}

	c, err := conn.Resolve(sessionPath)
	if err != nil {
		return err
	}

	// Create the service if it doesn't exist yet; reuse it otherwise.
	createErr := c.Do("POST", "/tenants/"+url.PathEscape(tenant)+"/services", nil, map[string]string{
		"name":      name,
		"auth_mode": *authMode,
	}, nil)
	switch {
	case createErr == nil:
		fmt.Fprintf(w, "created service %s/%s\n", tenant, name)
	case strings.HasPrefix(createErr.Error(), "conflict:"):
		fmt.Fprintf(w, "service %s/%s already exists; reusing it\n", tenant, name)
	default:
		return createErr
	}

	// Issue a fresh agent key (any previous key is revoked).
	var keyResp struct {
		AgentKey string `json:"agent_key"`
	}
	if err := c.Do("POST", "/tenants/"+url.PathEscape(tenant)+"/services/"+url.PathEscape(name)+"/agent-key", nil, nil, &keyResp); err != nil {
		return err
	}

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
		Server:   httpToWS(c.Base),
		Tenant:   tenant,
		Service:  name,
		AgentKey: keyResp.AgentKey,
		Upstream: "http://" + ln.Addr().String(),
	}
	cfg.Reconnect.InitialBackoff = config.Duration(time.Second)
	cfg.Reconnect.MaxBackoff = config.Duration(30 * time.Second)

	agentClient, err := agent.New(cfg)
	if err != nil {
		return err
	}

	fmt.Fprintf(w, "\npublic MCP endpoint:\n\n  %s/t/%s/s/%s/mcp\n\nuse OAuth in your MCP client; press Ctrl-C to stop.\n", c.Base, tenant, name)

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
