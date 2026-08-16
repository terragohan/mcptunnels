// Package bridge runs a stdio MCP server as a child process and exposes it
// over a local HTTP endpoint implementing the MCP "Streamable HTTP" transport
// (single endpoint, POST for requests, GET for the SSE stream of
// server-initiated messages). It exists so `mcptunnel expose` can point the
// tunnel agent at any MCP server command, ngrok-style.
package bridge

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os/exec"
	"strings"
	"sync"
)

const (
	maxBody    = 4 << 20  // 4 MiB inbound JSON-RPC message
	maxLine    = 32 << 20 // 32 MiB stdout line (large tool results)
	notifQueue = 256
)

// envelope is just enough of a JSON-RPC message to route it.
type envelope struct {
	ID     *json.RawMessage `json:"id"`
	Method string           `json:"method"`
}

// Server bridges one stdio MCP child process to HTTP. It is an http.Handler.
type Server struct {
	cmd    *exec.Cmd
	stdin  io.WriteCloser
	cancel context.CancelFunc

	mu      sync.Mutex // guards stdin writes and pending
	pending map[string]chan json.RawMessage

	notifs chan json.RawMessage // server-initiated messages for the SSE stream

	done    chan struct{} // closed when the child exits
	err     error         // child exit error, valid after done is closed
	session string
}

// Start launches name with args and returns a running bridge. The child is
// killed when ctx is canceled.
func Start(ctx context.Context, name string, args ...string) (*Server, error) {
	cctx, cancel := context.WithCancel(ctx)
	cmd := exec.CommandContext(cctx, name, args...)
	cmd.WaitDelay = 0 // default; kill promptly on cancel
	stdin, err := cmd.StdinPipe()
	if err != nil {
		cancel()
		return nil, err
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		cancel()
		return nil, err
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		cancel()
		return nil, err
	}
	if err := cmd.Start(); err != nil {
		cancel()
		return nil, fmt.Errorf("start %q: %w", name, err)
	}

	sid := make([]byte, 16)
	rand.Read(sid)

	s := &Server{
		cmd:     cmd,
		stdin:   stdin,
		cancel:  cancel,
		pending: map[string]chan json.RawMessage{},
		notifs:  make(chan json.RawMessage, notifQueue),
		done:    make(chan struct{}),
		session: hex.EncodeToString(sid),
	}
	go s.readLoop(stdout)
	go s.logStderr(stderr)
	go func() {
		err := cmd.Wait()
		s.mu.Lock()
		s.err = err
		// Fail every pending request so callers get a 502 instead of hanging.
		for k, ch := range s.pending {
			close(ch)
			delete(s.pending, k)
		}
		s.mu.Unlock()
		close(s.done)
	}()
	return s, nil
}

// Done is closed when the child process exits.
func (s *Server) Done() <-chan struct{} { return s.done }

// Err reports why the child exited; valid only after Done is closed.
func (s *Server) Err() error {
	<-s.done
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.err
}

// Close kills the child and releases resources.
func (s *Server) Close() { s.cancel() }

func (s *Server) readLoop(r io.Reader) {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64<<10), maxLine)
	for sc.Scan() {
		line := sc.Bytes()
		if len(strings.TrimSpace(string(line))) == 0 {
			continue
		}
		var env envelope
		if err := json.Unmarshal(line, &env); err != nil {
			slog.Warn("bridge: ignoring non-JSON line from child", "err", err)
			continue
		}
		msg := json.RawMessage(append([]byte(nil), line...))
		if env.ID != nil {
			key := string(*env.ID)
			s.mu.Lock()
			ch, ok := s.pending[key]
			s.mu.Unlock()
			if ok {
				ch <- msg // buffered (1); the waiter is already there
				continue
			}
		}
		// Notification or server-initiated request: queue for the SSE stream.
		select {
		case s.notifs <- msg:
		default:
			slog.Warn("bridge: dropping server-initiated message, SSE queue full")
		}
	}
}

func (s *Server) logStderr(r io.Reader) {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64<<10), 1<<20)
	for sc.Scan() {
		slog.Debug("mcp child stderr", "line", sc.Text())
	}
}

// ServeHTTP implements the Streamable HTTP transport on any path.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Mcp-Session-Id", s.session)
	select {
	case <-s.done:
		http.Error(w, "mcp server process has exited", http.StatusBadGateway)
		return
	default:
	}
	switch r.Method {
	case http.MethodPost:
		s.handlePost(w, r)
	case http.MethodGet:
		s.handleGet(w, r)
	case http.MethodDelete:
		w.WriteHeader(http.StatusOK) // session termination; nothing to do
	default:
		w.Header().Set("Allow", "GET, POST, DELETE")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *Server) handlePost(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(io.LimitReader(r.Body, maxBody+1))
	if err != nil || len(body) > maxBody {
		http.Error(w, "bad request body", http.StatusBadRequest)
		return
	}
	var env envelope
	if err := json.Unmarshal(body, &env); err != nil {
		http.Error(w, "body must be a single JSON-RPC object", http.StatusBadRequest)
		return
	}

	// Response or notification from the client: forward, no reply expected.
	if env.Method == "" || env.ID == nil {
		if err := s.send(body); err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		w.WriteHeader(http.StatusAccepted)
		return
	}

	// Request: forward and wait for the matching response by id.
	key := string(*env.ID)
	ch := make(chan json.RawMessage, 1)
	s.mu.Lock()
	s.pending[key] = ch
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		delete(s.pending, key)
		s.mu.Unlock()
	}()

	if err := s.send(body); err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}

	select {
	case resp, ok := <-ch:
		if !ok {
			http.Error(w, "mcp server process exited mid-request", http.StatusBadGateway)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write(resp)
	case <-s.done:
		http.Error(w, "mcp server process exited mid-request", http.StatusBadGateway)
	case <-r.Context().Done():
		// client went away; deregister via defer
	}
}

func (s *Server) handleGet(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.WriteHeader(http.StatusOK)
	fl, _ := w.(http.Flusher)
	if fl != nil {
		fl.Flush()
	}
	for {
		select {
		case msg := <-s.notifs:
			fmt.Fprintf(w, "event: message\ndata: %s\n\n", msg)
			if fl != nil {
				fl.Flush()
			}
		case <-s.done:
			return
		case <-r.Context().Done():
			return
		}
	}
}

// send writes one JSON-RPC message (newline-delimited, per MCP stdio) to the
// child's stdin.
func (s *Server) send(msg []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	select {
	case <-s.done:
		return fmt.Errorf("mcp server process has exited")
	default:
	}
	if _, err := s.stdin.Write(append(msg, '\n')); err != nil {
		return fmt.Errorf("write to mcp server: %w", err)
	}
	return nil
}
