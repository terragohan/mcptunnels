package proxy_test

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/terragohan/mcptunnels/internal/agent"
	"github.com/terragohan/mcptunnels/internal/config"
	"github.com/terragohan/mcptunnels/internal/gateway"
	"github.com/terragohan/mcptunnels/internal/proxy"
	"github.com/terragohan/mcptunnels/internal/store"
	"github.com/terragohan/mcptunnels/internal/store/storetest"
	"github.com/terragohan/mcptunnels/internal/tunnelproto"
)

// TestM1EndToEnd spins up tunneld (plain HTTP = "disabled" TLS mode), a dummy
// upstream, and an in-process agent, then drives traffic through the tunnel.
func TestM1EndToEnd(t *testing.T) {
	// Dummy upstream: echoes request line/headers/body, streams SSE.
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/echo":
			body, _ := io.ReadAll(r.Body)
			fmt.Fprintf(w, "method=%s path=%s x-echo=%s body=%s",
				r.Method, r.URL.Path, r.Header.Get("X-Echo"), body)
		case "/sse":
			w.Header().Set("Content-Type", "text/event-stream")
			fl, ok := w.(http.Flusher)
			if !ok {
				http.Error(w, "no flusher", http.StatusInternalServerError)
				return
			}
			for i := 1; i <= 3; i++ {
				fmt.Fprintf(w, "data: event-%d\n\n", i)
				fl.Flush()
				time.Sleep(100 * time.Millisecond)
			}
		default:
			http.NotFound(w, r)
		}
	}))
	defer upstream.Close()

	// Store-backed tenant + service + agent key.
	st := storetest.Open(t)
	if err := st.CreateTenant("acme", ""); err != nil {
		t.Fatal(err)
	}
	agentKey, err := st.CreateService("acme", &store.Service{Name: "demo"})
	if err != nil {
		t.Fatal(err)
	}

	// tunneld, in-process: gateway + public router on one listener.
	gw := gateway.New(st)
	mux := http.NewServeMux()
	mux.Handle(tunnelproto.ConnectPath, gw)
	mux.HandleFunc("GET /healthz", proxy.Healthz)
	mux.Handle("/t/{tenant}/s/", proxy.New(gw, st, nil))
	tunneld := httptest.NewServer(mux)
	defer tunneld.Close()

	// Agent, in-process, pointed at tunneld and the upstream.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	agentCfg := &config.AgentConfig{
		Server:   "ws://" + tunneld.Listener.Addr().String(),
		Tenant:   "acme",
		AgentKey: agentKey,
		Service:  "demo",
		Upstream: upstream.URL,
	}
	agentCfg.Reconnect.InitialBackoff = config.Duration(10 * time.Millisecond)
	agentCfg.Reconnect.MaxBackoff = config.Duration(200 * time.Millisecond)
	client, err := agent.New(agentCfg)
	if err != nil {
		t.Fatalf("agent.New: %v", err)
	}
	go client.Run(ctx) //nolint:errcheck // test teardown cancels ctx

	// Wait for the tunnel to come up.
	deadline := time.Now().Add(5 * time.Second)
	for !gw.Online("acme", "demo") {
		if time.Now().After(deadline) {
			t.Fatal("agent did not connect within 5s")
		}
		time.Sleep(10 * time.Millisecond)
	}

	base := tunneld.URL + "/t/acme/s/demo"

	t.Run("healthz", func(t *testing.T) {
		resp, err := http.Get(tunneld.URL + "/healthz")
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("healthz: got %d, want 200", resp.StatusCode)
		}
	})

	t.Run("get echo", func(t *testing.T) {
		req, _ := http.NewRequest(http.MethodGet, base+"/echo", nil)
		req.Header.Set("X-Echo", "hello")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("got %d, want 200 (body %q)", resp.StatusCode, body)
		}
		got := string(body)
		if !strings.Contains(got, "method=GET") || !strings.Contains(got, "path=/echo") || !strings.Contains(got, "x-echo=hello") {
			t.Fatalf("unexpected echo response: %q", got)
		}
	})

	t.Run("post body round-trip", func(t *testing.T) {
		resp, err := http.Post(base+"/echo", "text/plain", strings.NewReader("ping-pong-body"))
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)
		if !strings.Contains(string(body), "body=ping-pong-body") {
			t.Fatalf("body did not round-trip: %q", body)
		}
	})

	t.Run("sse streams incrementally", func(t *testing.T) {
		resp, err := http.Get(base + "/sse")
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("got %d, want 200", resp.StatusCode)
		}

		start := time.Now()
		var events []string
		var firstAt time.Time
		scanner := bufio.NewScanner(resp.Body)
		for scanner.Scan() && len(events) < 3 {
			line := scanner.Text()
			if !strings.HasPrefix(line, "data:") {
				continue
			}
			if firstAt.IsZero() {
				firstAt = time.Now()
			}
			events = append(events, line)
		}
		if err := scanner.Err(); err != nil {
			t.Fatalf("reading SSE stream: %v", err)
		}
		if len(events) != 3 {
			t.Fatalf("got %d events, want 3: %v", len(events), events)
		}
		for i, ev := range events {
			if want := fmt.Sprintf("data: event-%d", i+1); ev != want {
				t.Fatalf("event %d: got %q, want %q", i, ev, want)
			}
		}
		// The upstream sleeps 100ms between events; if the tunnel buffered the
		// whole response, the first event would only arrive after ~300ms.
		if elapsed := firstAt.Sub(start); elapsed > 150*time.Millisecond {
			t.Fatalf("first SSE event arrived after %v; response was buffered, not streamed", elapsed)
		}
	})

	t.Run("unknown service is 502", func(t *testing.T) {
		// The service exists in the store (created below) but has no agent.
		if _, err := st.CreateService("acme", &store.Service{Name: "offline"}); err != nil {
			t.Fatal(err)
		}
		resp, err := http.Get(tunneld.URL + "/t/acme/s/offline/echo")
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusBadGateway {
			t.Fatalf("got %d, want 502", resp.StatusCode)
		}
	})
}
