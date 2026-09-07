// Package stdiofront is the mirror image of bridge: it speaks MCP on stdio
// (a client on stdin/stdout) and forwards to a remote streamable-HTTP MCP
// endpoint. It exists so `mcptunnel run` can plug HTTP MCP servers — notably
// bearer-authenticated ones — into stdio-only MCP clients.
package stdiofront

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

const maxLine = 32 << 20 // 32 MiB stdio line (large tool results)

// envelope is just enough of a JSON-RPC message to route it.
type envelope struct {
	ID     *json.RawMessage `json:"id"`
	Method string           `json:"method"`
}

// Server bridges stdio to one remote streamable-HTTP MCP endpoint.
type Server struct {
	upstream *url.URL
	headers  http.Header
	hc       *http.Client

	mu      sync.Mutex // guards session and initMsg
	session string
	initMsg []byte // last initialize request, for re-init after expiry

	outMu sync.Mutex // serializes stdout lines
	out   io.Writer

	streamOnce sync.Once
	wg         sync.WaitGroup // in-flight requests, drained on shutdown
}

// Serve bridges stdio (an MCP client on stdin/stdout) to the remote endpoint
// until ctx is canceled or stdin reaches EOF, then terminates the upstream
// session best-effort. Diagnostics go to stderr via slog; stdout carries only
// JSON-RPC.
func Serve(ctx context.Context, stdin io.Reader, stdout io.Writer, upstream *url.URL, headers http.Header, transport http.RoundTripper) error {
	s := &Server{
		upstream: upstream,
		headers:  headers,
		out:      stdout,
		hc: &http.Client{
			// Transport injects the registry bearer token when configured
			// (nil → default). No overall timeout: streamed (SSE) responses
			// may stay open indefinitely. Never follow redirects — pass them
			// through.
			Transport: transport,
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}

	lines := make(chan []byte, 16)
	go scanLines(stdin, lines)

	for {
		select {
		case line, ok := <-lines:
			if !ok {
				s.drain()
				s.closeSession()
				return nil
			}
			s.handleLine(ctx, line)
		case <-ctx.Done():
			s.drain()
			s.closeSession()
			return nil
		}
	}
}

// drain waits briefly for in-flight requests to finish writing their
// responses, so a client that closes stdin right after its last request (the
// common `echo … | mcptunnel run` pattern) still gets the reply.
func (s *Server) drain() {
	done := make(chan struct{})
	go func() {
		s.wg.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		slog.Warn("stdiofront: giving up on in-flight requests after 5s")
	}
}

func scanLines(r io.Reader, out chan<- []byte) {
	defer close(out)
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64<<10), maxLine)
	for sc.Scan() {
		line := bytes.TrimSpace(sc.Bytes())
		if len(line) > 0 {
			out <- append([]byte(nil), line...)
		}
	}
}

// handleLine routes one JSON-RPC message from the client.
func (s *Server) handleLine(ctx context.Context, line []byte) {
	var env envelope
	if err := json.Unmarshal(line, &env); err != nil {
		slog.Warn("stdiofront: ignoring non-JSON line from client", "err", err)
		return
	}

	// Request: forward and deliver the matching response on stdout.
	if env.ID != nil && env.Method != "" {
		msg := append([]byte(nil), line...)
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			s.request(ctx, msg, env)
		}()
		return
	}
	// Notification, or a response to a server-initiated request: forward
	// fire-and-forget; nothing comes back on stdout.
	resp, err := s.post(ctx, line)
	if err != nil {
		slog.Warn("stdiofront: forwarding message failed", "method", env.Method, "err", err)
		return
	}
	resp.Body.Close()
}

// request forwards one client request upstream and writes the response (and
// any interleaved server messages) to stdout.
func (s *Server) request(ctx context.Context, msg []byte, env envelope) {
	id := string(*env.ID)
	resp, err := s.post(ctx, msg)
	if err != nil {
		slog.Warn("stdiofront: upstream request failed", "method", env.Method, "err", err)
		s.writeError(id, err)
		return
	}
	defer resp.Body.Close()

	if env.Method == "initialize" && resp.StatusCode/100 == 2 {
		s.mu.Lock()
		s.initMsg = append([]byte(nil), msg...)
		if sid := resp.Header.Get("Mcp-Session-Id"); sid != "" {
			s.session = sid
		}
		s.mu.Unlock()
		s.streamOnce.Do(func() { go s.stream(ctx) })
	}

	if resp.StatusCode/100 != 2 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		s.writeError(id, fmt.Errorf("upstream returned %s: %s", resp.Status, bytes.TrimSpace(body)))
		return
	}

	if strings.HasPrefix(resp.Header.Get("Content-Type"), "text/event-stream") {
		s.readSSEResponse(resp.Body, id)
		return
	}
	line, err := io.ReadAll(io.LimitReader(resp.Body, maxLine+1))
	if err != nil || len(bytes.TrimSpace(line)) == 0 {
		s.writeError(id, fmt.Errorf("reading upstream response: %w", err))
		return
	}
	s.writeLine(bytes.TrimSpace(line))
}

// post sends one message upstream with session and injected headers. On 404
// with a live session it transparently re-initializes and retries once.
func (s *Server) post(ctx context.Context, msg []byte) (*http.Response, error) {
	resp, err := s.doPost(ctx, msg)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusNotFound || s.getSession() == "" {
		return resp, nil
	}
	resp.Body.Close()
	slog.Info("stdiofront: session expired, re-initializing")
	if err := s.reinit(ctx); err != nil {
		return nil, err
	}
	return s.doPost(ctx, msg)
}

func (s *Server) doPost(ctx context.Context, msg []byte) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.upstream.String(), bytes.NewReader(msg))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	if sid := s.getSession(); sid != "" {
		req.Header.Set("Mcp-Session-Id", sid)
	}
	copyHeaders(req.Header, s.headers)
	return s.hc.Do(req)
}

// reinit replays the cached initialize request without a session id and
// stores the fresh session.
func (s *Server) reinit(ctx context.Context) error {
	s.mu.Lock()
	initMsg := s.initMsg
	s.session = ""
	s.mu.Unlock()
	if initMsg == nil {
		return fmt.Errorf("session expired and no initialize request cached")
	}
	resp, err := s.doPost(ctx, initMsg)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("re-initialize: upstream returned %s", resp.Status)
	}
	if sid := resp.Header.Get("Mcp-Session-Id"); sid != "" {
		s.mu.Lock()
		s.session = sid
		s.mu.Unlock()
	}
	return nil
}

// stream follows the server-initiated message stream (GET + SSE) until ctx
// ends, writing every message to stdout. Servers that don't implement it
// (405) disable the stream for the rest of the session.
func (s *Server) stream(ctx context.Context) {
	backoff := 200 * time.Millisecond
	for {
		if ctx.Err() != nil {
			return
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.upstream.String(), nil)
		if err != nil {
			return
		}
		req.Header.Set("Accept", "text/event-stream")
		if sid := s.getSession(); sid != "" {
			req.Header.Set("Mcp-Session-Id", sid)
		}
		copyHeaders(req.Header, s.headers)
		resp, err := s.hc.Do(req)
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			slog.Debug("stdiofront: GET stream failed, retrying", "err", err, "backoff", backoff)
			if !sleep(ctx, backoff) {
				return
			}
			backoff *= 2
			if backoff > 5*time.Second {
				backoff = 5 * time.Second
			}
			continue
		}
		if resp.StatusCode == http.StatusMethodNotAllowed {
			resp.Body.Close()
			slog.Debug("stdiofront: upstream has no GET stream; server-initiated messages disabled")
			return
		}
		if resp.StatusCode/100 != 2 {
			body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
			resp.Body.Close()
			slog.Debug("stdiofront: GET stream rejected, retrying", "status", resp.Status, "body", string(body))
			if !sleep(ctx, backoff) {
				return
			}
			continue
		}
		backoff = 200 * time.Millisecond
		s.readEvents(resp.Body, "")
		resp.Body.Close()
	}
}

// readSSEResponse consumes a POST response delivered as an event stream: the
// message matching the request id completes it; any other messages (server
// notifications or requests) go to stdout as usual.
func (s *Server) readSSEResponse(r io.Reader, wantID string) {
	s.readEvents(r, wantID)
}

// readEvents parses SSE events from r until EOF. Events whose data parses as
// a JSON-RPC message are written to stdout, except the message whose id
// equals wantID, which terminates the read (caller handles it as the
// response). wantID == "" means "never terminate, write everything".
func (s *Server) readEvents(r io.Reader, wantID string) {
	br := bufio.NewReader(r)
	var data []byte
	for {
		line, err := br.ReadString('\n')
		if len(line) > 0 {
			line = strings.TrimRight(line, "\r\n")
			if line == "" {
				if len(data) > 0 && !s.dispatch(data, wantID) {
					return
				}
				data = nil
			} else if rest, ok := strings.CutPrefix(line, "data:"); ok {
				rest = strings.TrimPrefix(rest, " ")
				data = append(data, rest...)
				data = append(data, '\n')
			}
			// comment lines ("#…") and other fields are ignored
		}
		if err != nil {
			if len(data) > 0 {
				s.dispatch(data, wantID)
			}
			return
		}
	}
}

// dispatch handles one complete SSE event payload. It reports false when the
// wanted response arrived (readEvents should stop).
func (s *Server) dispatch(data []byte, wantID string) bool {
	line := bytes.TrimSpace(data)
	if len(line) == 0 {
		return true
	}
	if wantID != "" {
		var env envelope
		if err := json.Unmarshal(line, &env); err == nil && env.ID != nil && string(*env.ID) == wantID {
			s.writeLine(line) // the response itself completes the request
			return false
		}
	}
	s.writeLine(line)
	return true
}

// writeError synthesizes a JSON-RPC error response so a failed request
// doesn't leave the client hanging.
func (s *Server) writeError(id string, err error) {
	msg := fmt.Sprintf(`{"jsonrpc":"2.0","id":%s,"error":{"code":-32603,"message":%s}}`,
		id, jsonQuote(err.Error()))
	s.writeLine([]byte(msg))
}

func (s *Server) writeLine(line []byte) {
	s.outMu.Lock()
	defer s.outMu.Unlock()
	s.out.Write(append(line, '\n'))
	if w, ok := s.out.(interface{ Flush() error }); ok {
		w.Flush()
	}
}

// closeSession terminates the upstream session best-effort (DELETE per the
// streamable-HTTP spec).
func (s *Server) closeSession() {
	sid := s.getSession()
	if sid == "" {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, s.upstream.String(), nil)
	if err != nil {
		return
	}
	req.Header.Set("Mcp-Session-Id", sid)
	copyHeaders(req.Header, s.headers)
	resp, err := s.hc.Do(req)
	if err != nil {
		return
	}
	resp.Body.Close()
}

func (s *Server) getSession() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.session
}

func copyHeaders(dst, src http.Header) {
	for k, vals := range src {
		dst[http.CanonicalHeaderKey(k)] = vals
	}
}

func jsonQuote(s string) string {
	b, _ := json.Marshal(s)
	return string(b)
}

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
