// Package agent implements the tunnel-agent client: it dials outbound to
// tunneld, serves yamux streams, and executes each proxied HTTP request
// against the local upstream.
package agent

import (
	"bufio"
	"context"
	"fmt"
	"log/slog"
	"math/rand"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/coder/websocket"
	"github.com/hashicorp/yamux"

	"github.com/terragohan/mcptunnels/internal/config"
	"github.com/terragohan/mcptunnels/internal/tunnelproto"
)

// Client maintains an outbound tunnel to tunneld and forwards requests to the
// local upstream.
type Client struct {
	server   string // full ws(s) URL of the connect endpoint
	key      string
	tenant   string
	service  string
	upstream *url.URL

	initialBackoff time.Duration
	maxBackoff     time.Duration

	httpClient *http.Client
}

// New builds a Client from the agent configuration.
func New(cfg *config.AgentConfig) (*Client, error) {
	upstream, err := url.Parse(cfg.Upstream)
	if err != nil {
		return nil, fmt.Errorf("invalid upstream URL: %w", err)
	}
	if upstream.Scheme == "" || upstream.Host == "" {
		return nil, fmt.Errorf("upstream must be an absolute URL like http://localhost:3000")
	}
	return &Client{
		server:         strings.TrimRight(cfg.Server, "/") + tunnelproto.ConnectPath,
		key:            cfg.AgentKey,
		tenant:         cfg.Tenant,
		service:        cfg.Service,
		upstream:       upstream,
		initialBackoff: cfg.Reconnect.InitialBackoff.D(),
		maxBackoff:     cfg.Reconnect.MaxBackoff.D(),
		httpClient: &http.Client{
			// No overall timeout: streamed (SSE) responses may stay open
			// indefinitely. Never follow redirects — pass them through.
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}, nil
}

// Run connects to tunneld and serves until ctx is canceled. It reconnects
// automatically with exponential backoff (jittered) on any failure.
func (c *Client) Run(ctx context.Context) error {
	backoff := c.initialBackoff
	for {
		err := c.serve(ctx)
		if ctx.Err() != nil {
			return ctx.Err()
		}
		slog.Warn("agent: tunnel down, reconnecting", "err", err, "retry_in", backoff)
		if !sleep(ctx, jitter(backoff)) {
			return ctx.Err()
		}
		backoff *= 2
		if backoff > c.maxBackoff {
			backoff = c.maxBackoff
		}
	}
}

// serve establishes one tunnel and serves it until it breaks.
func (c *Client) serve(ctx context.Context) error {
	header := http.Header{}
	header.Set("Authorization", tunnelproto.AuthorizationHeader(c.key))
	header.Set(tunnelproto.HeaderTenant, c.tenant)
	header.Set(tunnelproto.HeaderServiceName, c.service)

	ws, _, err := websocket.Dial(ctx, c.server, &websocket.DialOptions{HTTPHeader: header})
	if err != nil {
		return fmt.Errorf("dial %s: %w", c.server, err)
	}

	conn := websocket.NetConn(ctx, ws, websocket.MessageBinary)
	sess, err := yamux.Server(conn, nil)
	if err != nil {
		conn.Close()
		return fmt.Errorf("yamux server: %w", err)
	}
	defer sess.Close()
	slog.Info("agent: connected", "server", c.server, "service", c.service)

	for {
		stream, err := sess.Accept()
		if err != nil {
			return fmt.Errorf("accept stream: %w", err)
		}
		go c.handleStream(stream)
	}
}

// handleStream reads one HTTP request from the stream, executes it against
// the upstream, and writes the response back to the stream.
func (c *Client) handleStream(stream net.Conn) {
	defer stream.Close()

	req, err := http.ReadRequest(bufio.NewReader(stream))
	if err != nil {
		slog.Warn("agent: read request failed", "err", err)
		return
	}
	defer req.Body.Close()

	req.URL.Scheme = c.upstream.Scheme
	req.URL.Host = c.upstream.Host
	req.RequestURI = ""

	resp, err := c.httpClient.Do(req)
	if err != nil {
		slog.Warn("agent: upstream request failed", "url", req.URL, "err", err)
		writeError(stream, http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	// Response.Write streams the body through as it is read, and closing the
	// yamux stream afterwards half-closes it so the gateway sees EOF.
	if err := resp.Write(stream); err != nil {
		slog.Warn("agent: write response failed", "url", req.URL, "err", err)
	}
}

func writeError(w net.Conn, status int) {
	resp := &http.Response{
		StatusCode:    status,
		Status:        fmt.Sprintf("%d %s", status, http.StatusText(status)),
		Proto:         "HTTP/1.1",
		ProtoMajor:    1,
		ProtoMinor:    1,
		Body:          http.NoBody,
		ContentLength: 0,
		Header:        http.Header{"Content-Type": {"text/plain"}},
	}
	if err := resp.Write(w); err != nil {
		slog.Debug("agent: write error response failed", "err", err)
	}
}

func jitter(d time.Duration) time.Duration {
	// ±25% jitter.
	delta := d / 4
	return d - delta + time.Duration(rand.Int63n(int64(2*delta)+1))
}

// sleep waits for d, returning false if ctx is canceled first.
func sleep(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}
