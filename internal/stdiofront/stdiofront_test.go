package stdiofront_test

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"testing"
	"time"

	"github.com/terragohan/mcptunnels/internal/stdiofront"
	"github.com/terragohan/mcptunnels/internal/tokencache"
)

// fakeUpstream is a controllable streamable-HTTP MCP endpoint.
type fakeUpstream struct {
	srv *httptest.Server

	mu         sync.Mutex
	session    string
	expireNext bool // next valid-session POST gets a one-shot 404
	ssePost    bool // deliver POST responses as SSE events
	stream     bool // implement the GET stream (else 405)
	deleted    bool // a DELETE (session termination) arrived
	posts      []http.Header

	pushCh chan string // messages to send down the GET stream
}

func newFakeUpstream(t *testing.T) *fakeUpstream {
	f := &fakeUpstream{pushCh: make(chan string, 16)}
	f.srv = httptest.NewServer(http.HandlerFunc(f.handle))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeUpstream) handle(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	f.posts = append(f.posts, r.Header.Clone())
	session, expireNext, ssePost, stream := f.session, f.expireNext, f.ssePost, f.stream
	f.mu.Unlock()

	body, _ := io.ReadAll(r.Body)
	var env struct {
		ID     json.RawMessage `json:"id"`
		Method string          `json:"method"`
	}
	json.Unmarshal(body, &env)

	switch r.Method {
	case http.MethodPost:
		if sid := r.Header.Get("Mcp-Session-Id"); session != "" && sid != session {
			http.Error(w, `{"error":"session not found"}`, http.StatusNotFound)
			return
		}
		f.mu.Lock()
		if expireNext {
			f.expireNext = false
			f.mu.Unlock()
			http.Error(w, `{"error":"session expired"}`, http.StatusNotFound)
			return
		}
		f.mu.Unlock()

		if env.Method == "initialize" {
			f.mu.Lock()
			f.session = "sess-1"
			f.mu.Unlock()
			w.Header().Set("Mcp-Session-Id", "sess-1")
		}
		if env.ID == nil {
			w.WriteHeader(http.StatusAccepted)
			return
		}
		reply := fmt.Sprintf(`{"jsonrpc":"2.0","id":%s,"result":{"ok":true}}`, env.ID)
		if !ssePost {
			w.Header().Set("Content-Type", "application/json")
			io.WriteString(w, reply)
			return
		}
		w.Header().Set("Content-Type", "text/event-stream")
		w.(http.Flusher).Flush()
		fmt.Fprintf(w, "event: message\ndata: %s\n\n", `{"jsonrpc":"2.0","method":"notifications/progress"}`)
		fmt.Fprintf(w, "event: message\ndata: %s\n\n", reply)
		w.(http.Flusher).Flush()

	case http.MethodGet:
		if !stream {
			http.Error(w, "stream not supported", http.StatusMethodNotAllowed)
			return
		}
		if sid := r.Header.Get("Mcp-Session-Id"); session != "" && sid != session {
			http.Error(w, `{"error":"session not found"}`, http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "text/event-stream")
		w.(http.Flusher).Flush()
		for {
			select {
			case msg := <-f.pushCh:
				fmt.Fprintf(w, "event: message\ndata: %s\n\n", msg)
				w.(http.Flusher).Flush()
			case <-r.Context().Done():
				return
			}
		}

	case http.MethodDelete:
		f.mu.Lock()
		f.deleted = true
		f.mu.Unlock()
		w.WriteHeader(http.StatusOK)

	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (f *fakeUpstream) url(t *testing.T) *url.URL {
	t.Helper()
	u, err := url.Parse(f.srv.URL + "/mcp")
	if err != nil {
		t.Fatal(err)
	}
	return u
}

func (f *fakeUpstream) seen(t *testing.T, header, value string) bool {
	t.Helper()
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, h := range f.posts {
		if h.Get(header) == value {
			return true
		}
	}
	return false
}

// session starts stdiofront.Serve against the fake upstream and returns
// handles to talk to it: send writes one client message line, read waits for
// one stdout line (with timeout).
type session struct {
	t      *testing.T
	cancel context.CancelFunc
	send   func(string)
	close  func() // close stdin (EOF)
	lines  <-chan string
}

func start(t *testing.T, f *fakeUpstream, headers map[string][]string) *session {
	t.Helper()
	return startWithTransport(t, f, headers, nil)
}

func startWithTransport(t *testing.T, f *fakeUpstream, headers map[string][]string, transport http.RoundTripper) *session {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	stdinR, stdinW := io.Pipe()
	outCh := make(chan string, 64)
	// stdout pump
	outR, outW := io.Pipe()
	go func() {
		sc := bufio.NewScanner(outR)
		for sc.Scan() {
			outCh <- sc.Text()
		}
	}()
	go func() {
		_ = stdiofront.Serve(ctx, stdinR, outW, f.url(t), headers, transport)
		outW.Close()
	}()
	t.Cleanup(cancel)
	return &session{
		t:      t,
		cancel: cancel,
		send:   func(line string) { stdinW.Write([]byte(line + "\n")) },
		close:  func() { stdinW.Close() },
		lines:  outCh,
	}
}

func (s *session) read() string {
	s.t.Helper()
	select {
	case line := <-s.lines:
		return line
	case <-time.After(5 * time.Second):
		s.t.Fatal("timed out waiting for a stdout line")
		return ""
	}
}

func hasID(t *testing.T, line string, want float64) bool {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal([]byte(line), &m); err != nil {
		return false
	}
	id, ok := m["id"].(float64)
	return ok && id == want
}

func TestJSONResponsesAndSession(t *testing.T) {
	f := newFakeUpstream(t)
	s := start(t, f, map[string][]string{"Authorization": {"Bearer key"}})

	s.send(`{"jsonrpc":"2.0","id":1,"method":"initialize"}`)
	if line := s.read(); !hasID(t, line, 1) {
		t.Fatalf("initialize reply = %s", line)
	}
	s.send(`{"jsonrpc":"2.0","id":2,"method":"tools/list"}`)
	if line := s.read(); !hasID(t, line, 2) {
		t.Fatalf("tools/list reply = %s", line)
	}

	if !f.seen(t, "Mcp-Session-Id", "sess-1") {
		t.Error("upstream never saw the captured Mcp-Session-Id")
	}
	if !f.seen(t, "Authorization", "Bearer key") {
		t.Error("injected Authorization header never reached the upstream")
	}
}

// TestTransportInjectsRegistryToken passes a tokencache.Transport to Serve
// and asserts the registry bearer token reaches the upstream.
func TestTransportInjectsRegistryToken(t *testing.T) {
	f := newFakeUpstream(t)
	store := &tokencache.Store{Dir: t.TempDir()}
	e := &tokencache.Entry{URL: f.url(t).String(), AccessToken: "registry-key"}
	if err := store.Save(e); err != nil {
		t.Fatal(err)
	}
	s := startWithTransport(t, f, nil, &tokencache.Transport{Source: tokencache.NewSource(store, e)})

	s.send(`{"jsonrpc":"2.0","id":1,"method":"initialize"}`)
	if line := s.read(); !hasID(t, line, 1) {
		t.Fatalf("initialize reply = %s", line)
	}
	if !f.seen(t, "Authorization", "Bearer registry-key") {
		t.Error("registry token never reached the upstream")
	}
}

func TestSSEResponse(t *testing.T) {
	f := newFakeUpstream(t)
	f.ssePost = true
	s := start(t, f, nil)

	s.send(`{"jsonrpc":"2.0","id":1,"method":"initialize"}`)
	first, second := s.read(), s.read()
	got := map[string]bool{}
	for _, line := range []string{first, second} {
		var m map[string]any
		if err := json.Unmarshal([]byte(line), &m); err != nil {
			t.Fatalf("stdout line is not JSON: %q", line)
		}
		if m["method"] == "notifications/progress" {
			got["notification"] = true
		}
		if hasID(t, line, 1) {
			got["response"] = true
		}
	}
	if !got["notification"] || !got["response"] {
		t.Fatalf("want interleaved notification + response; got %q and %q", first, second)
	}
}

func TestNotificationIsFireAndForget(t *testing.T) {
	f := newFakeUpstream(t)
	s := start(t, f, nil)

	s.send(`{"jsonrpc":"2.0","id":1,"method":"initialize"}`)
	s.read()
	s.send(`{"jsonrpc":"2.0","method":"notifications/initialized"}`)

	if !f.seen(t, "Accept", "application/json, text/event-stream") {
		t.Error("upstream never saw the streamable-HTTP Accept header")
	}
	select {
	case line := <-s.lines:
		t.Fatalf("notification must not produce stdout output, got %q", line)
	case <-time.After(300 * time.Millisecond):
	}
}

func TestGetStreamPushesToStdout(t *testing.T) {
	f := newFakeUpstream(t)
	f.stream = true
	s := start(t, f, nil)

	s.send(`{"jsonrpc":"2.0","id":1,"method":"initialize"}`)
	s.read()

	f.pushCh <- `{"jsonrpc":"2.0","method":"notifications/tools/list_changed"}`
	line := s.read()
	var m map[string]any
	if err := json.Unmarshal([]byte(line), &m); err != nil || m["method"] != "notifications/tools/list_changed" {
		t.Fatalf("GET stream message = %q", line)
	}
}

func TestSessionExpiryReinitializes(t *testing.T) {
	f := newFakeUpstream(t)
	s := start(t, f, nil)

	s.send(`{"jsonrpc":"2.0","id":1,"method":"initialize"}`)
	s.read()
	f.mu.Lock()
	f.expireNext = true
	f.mu.Unlock()

	s.send(`{"jsonrpc":"2.0","id":2,"method":"tools/list"}`)
	if line := s.read(); !hasID(t, line, 2) {
		t.Fatalf("reply after session expiry = %s", line)
	}

	// The re-init must have replayed initialize without a session header.
	f.mu.Lock()
	defer f.mu.Unlock()
	inits := 0
	for i, h := range f.posts {
		if h.Get("Mcp-Session-Id") == "" && i > 0 {
			inits++
		}
	}
	// f.posts[0] is the first initialize (no session). Exactly one more
	// session-less POST means the re-init happened.
	if inits != 1 {
		t.Errorf("session-less POSTs after the first = %d; want 1 (re-init)", inits)
	}
}

func TestShutdownDeletesSession(t *testing.T) {
	f := newFakeUpstream(t)
	s := start(t, f, nil)
	s.send(`{"jsonrpc":"2.0","id":1,"method":"initialize"}`)
	s.read()
	s.cancel()

	// The DELETE is best-effort on shutdown; give it a moment.
	deadline := time.Now().Add(2 * time.Second)
	for !f.deleteSeen() {
		if time.Now().After(deadline) {
			t.Fatal("no DELETE observed after shutdown")
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// deleteSeen reports whether any DELETE request arrived.
func (f *fakeUpstream) deleteSeen() bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.deleted
}

func TestEOFAfterRequestStillReplies(t *testing.T) {
	f := newFakeUpstream(t)
	s := start(t, f, nil)
	s.send(`{"jsonrpc":"2.0","id":1,"method":"initialize"}`)
	// Client closes stdin immediately — the reply must still arrive.
	s.close()
	if line := s.read(); !hasID(t, line, 1) {
		t.Fatalf("reply after stdin EOF = %s", line)
	}
}

func TestNonJSONIgnored(t *testing.T) {
	f := newFakeUpstream(t)
	s := start(t, f, nil)
	s.send("this is not json")
	s.send(`{"jsonrpc":"2.0","id":1,"method":"initialize"}`)
	if line := s.read(); !hasID(t, line, 1) {
		t.Fatalf("reply after garbage line = %s", line)
	}
}
