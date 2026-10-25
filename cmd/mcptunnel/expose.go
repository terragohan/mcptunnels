package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
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

	"github.com/terragohan/mcptunnels/internal/agent"
	"github.com/terragohan/mcptunnels/internal/bridge"
	"github.com/terragohan/mcptunnels/internal/cli"
	"github.com/terragohan/mcptunnels/internal/config"
)

// exposeOpts is the parsed form of the `mcptunnel expose` flags.
type exposeOpts struct {
	server      string
	configPath  string
	noAuth      bool
	upstreamURL string // --url mode; empty means stdio command mode
	headers     http.Header
	cmdArgs     []string // stdio MCP server command, everything after "--"
}

// parseExposeArgs splits args at "--" (everything after it is the MCP server
// command) and validates the flag combination. Usage problems come back as
// cli.UsageError.
func parseExposeArgs(args []string) (exposeOpts, error) {
	// Everything after "--" is the MCP server command.
	flagArgs, cmdArgs := args, []string(nil)
	for i, a := range args {
		if a == "--" {
			flagArgs, cmdArgs = args[:i], args[i+1:]
			break
		}
	}

	opts := exposeOpts{server: cli.DefaultServer, headers: http.Header{}}
	fs := cli.NewFlagSet("expose")
	fs.StringVar(&opts.server, "server", cli.DefaultServer, "tunneld base URL (defaults to the hosted "+cli.DefaultServer+")")
	fs.StringVar(&opts.configPath, "config", "", "tunneld.yaml to read the server URL from (same-host use)")
	fs.BoolVar(&opts.noAuth, "no-auth", false, "disable OAuth on the public endpoint (anyone with the URL can use it)")
	fs.StringVar(&opts.upstreamURL, "url", "", "expose a remote HTTP MCP server at this URL instead of a local command")
	fs.Var(headerFlag(opts.headers), "header", "header to send to the upstream, \"Name: value\" (repeatable)")
	pos, err := cli.ParseIntermixed(fs, flagArgs)
	if err != nil {
		return exposeOpts{}, cli.Usagef("%v", err)
	}
	switch {
	case len(pos) > 0:
		return exposeOpts{}, cli.Usagef("unexpected argument %q (flags go before the command; the MCP server command goes after --)", pos[0])
	case opts.upstreamURL != "" && len(cmdArgs) > 0:
		return exposeOpts{}, cli.Usagef("--url and a command are mutually exclusive")
	case opts.upstreamURL == "" && len(cmdArgs) == 0:
		return exposeOpts{}, cli.Usagef("usage: mcptunnel expose [--server URL | --config PATH] [--no-auth] [--header \"Name: value\"]... (-- <mcp server command> [args...] | --url URL)")
	}
	if opts.upstreamURL != "" {
		u, err := url.Parse(opts.upstreamURL)
		if err != nil || u.Scheme == "" || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") {
			return exposeOpts{}, cli.Usagef("--url must be an absolute http(s) URL, got %q", opts.upstreamURL)
		}
	}
	opts.cmdArgs = cmdArgs
	return opts, nil
}

// runExpose implements `mcptunnel expose [--server URL] (-- <cmd>... | --url URL)`:
// it creates an anonymous quick tunnel via POST /api/v1/quick and connects the
// tunnel agent to an upstream — either the given local stdio MCP server
// command behind a loopback HTTP bridge, or a remote HTTP MCP server URL.
// ngrok-style, one command from MCP server to public endpoint.
//
// OAuth is on by default: a random password is generated, sent to tunneld,
// and printed. The OAuth authorize endpoint requires it. --no-auth skips
// both. On Ctrl-C the tunnel is deleted via DELETE /api/v1/quick/{tenant}.
func runExpose(w io.Writer, args []string) error {
	opts, err := parseExposeArgs(args)
	if err != nil {
		return err
	}

	// --config wins only when --server was left at the hosted default.
	base := opts.server
	if base == cli.DefaultServer && opts.configPath != "" {
		s, err := cli.ServerFromConfig(opts.configPath)
		if err != nil {
			return err
		}
		base = s
	}

	auth := !opts.noAuth

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

	// Resolve the upstream: a local stdio MCP server behind the loopback
	// bridge, or a remote URL given via --url.
	upstream := opts.upstreamURL
	var b *bridge.Server
	if upstream == "" {
		bb, err := bridge.Start(ctx, opts.cmdArgs[0], opts.cmdArgs[1:]...)
		if err != nil {
			return fmt.Errorf("starting mcp server: %w", err)
		}
		b = bb
		defer b.Close()

		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			return err
		}
		defer ln.Close()
		httpSrv := &http.Server{Handler: b}
		go httpSrv.Serve(ln)
		defer httpSrv.Close()
		upstream = "http://" + ln.Addr().String()
	}

	cfg := &config.AgentConfig{
		Server:   httpToWS(base),
		Tenant:   resp.Tenant,
		Service:  resp.Service,
		AgentKey: resp.AgentKey,
		Upstream: upstream,
	}
	if len(opts.headers) > 0 {
		cfg.UpstreamHeaders = map[string][]string(opts.headers)
	}
	if t := tokenTransportFor(opts.upstreamURL, opts.headers); t != nil {
		cfg.Transport = t
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

	// In stdio mode, exit when the MCP server child dies too.
	var childDone <-chan struct{}
	if b != nil {
		childDone = b.Done()
	}

	select {
	case err := <-agentErr:
		if ctx.Err() != nil {
			return nil // interrupted by the user
		}
		return err
	case <-childDone:
		return fmt.Errorf("mcp server exited: %w", b.Err())
	}
}

// headerFlag adapts an http.Header for repeated --header "Name: value" flags.
type headerFlag http.Header

func (h headerFlag) String() string { return "" }

func (h headerFlag) Set(s string) error {
	name, value, ok := strings.Cut(s, ":")
	if !ok || strings.TrimSpace(name) == "" {
		return fmt.Errorf("invalid header %q, want \"Name: value\"", s)
	}
	http.Header(h).Add(strings.TrimSpace(name), strings.TrimSpace(value))
	return nil
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
