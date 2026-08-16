package bridge

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

func startCat(t *testing.T) (*Server, *httptest.Server) {
	t.Helper()
	b, err := Start(context.Background(), "cat")
	if err != nil {
		t.Fatalf("start cat: %v", err)
	}
	t.Cleanup(b.Close)
	ts := httptest.NewServer(b)
	t.Cleanup(ts.Close)
	return b, ts
}

func post(t *testing.T, url, body string) *http.Response {
	t.Helper()
	resp, err := http.Post(url, "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	return resp
}

func TestRequestResponse(t *testing.T) {
	_, ts := startCat(t)
	resp := post(t, ts.URL, `{"jsonrpc":"2.0","id":1,"method":"ping"}`)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status %d, want 200", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); ct != "application/json" {
		t.Fatalf("content-type %q", ct)
	}
	if sid := resp.Header.Get("Mcp-Session-Id"); sid == "" {
		t.Fatal("missing Mcp-Session-Id header")
	}
	data, _ := io.ReadAll(resp.Body)
	var env envelope
	if err := json.Unmarshal(data, &env); err != nil {
		t.Fatalf("response not JSON: %v (%s)", err, data)
	}
	if env.Method != "ping" {
		t.Fatalf("echoed method %q, want ping", env.Method)
	}
}

func TestNotificationAccepted(t *testing.T) {
	_, ts := startCat(t)
	resp := post(t, ts.URL, `{"jsonrpc":"2.0","method":"notifications/initialized"}`)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusAccepted {
		t.Fatalf("status %d, want 202", resp.StatusCode)
	}
}

func TestConcurrentRequestsCorrelate(t *testing.T) {
	_, ts := startCat(t)
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			resp := post(t, ts.URL, fmt.Sprintf(`{"jsonrpc":"2.0","id":%d,"method":"tools/list"}`, i))
			defer resp.Body.Close()
			if resp.StatusCode != http.StatusOK {
				t.Errorf("req %d: status %d", i, resp.StatusCode)
				return
			}
			data, _ := io.ReadAll(resp.Body)
			var env envelope
			if err := json.Unmarshal(data, &env); err != nil || env.ID == nil || string(*env.ID) != fmt.Sprint(i) {
				t.Errorf("req %d: bad correlation: %s", i, data)
			}
		}(i)
	}
	wg.Wait()
}

func TestChildExitGives502(t *testing.T) {
	b, err := Start(context.Background(), "sh", "-c", "exit 0")
	if err != nil {
		t.Fatalf("start: %v", err)
	}
	defer b.Close()
	ts := httptest.NewServer(b)
	defer ts.Close()

	deadline := time.Now().Add(5 * time.Second)
	for {
		resp := post(t, ts.URL, `{"jsonrpc":"2.0","id":1,"method":"ping"}`)
		resp.Body.Close()
		if resp.StatusCode == http.StatusBadGateway {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("never got 502 after child exit (last status %d)", resp.StatusCode)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func TestRejectsNonJSON(t *testing.T) {
	_, ts := startCat(t)
	resp := post(t, ts.URL, `not json`)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status %d, want 400", resp.StatusCode)
	}
}
