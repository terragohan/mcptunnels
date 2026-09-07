package main

import (
	"net/http"
	"testing"
)

func TestParseTokenAddHappyPath(t *testing.T) {
	opts, err := parseTokenAddArgs([]string{
		"--url", "https://api.example.com/mcp",
		"--bearer", "tok",
		"--refresh-token", "ref",
		"--token-url", "https://auth.example.com/token",
		"--client-id", "client-1",
		"--expires-in", "3600",
	})
	if err != nil {
		t.Fatalf("parseTokenAddArgs: %v", err)
	}
	if opts.url != "https://api.example.com/mcp" || opts.bearer != "tok" ||
		opts.refreshToken != "ref" || opts.tokenURL != "https://auth.example.com/token" ||
		opts.clientID != "client-1" || opts.expiresIn != 3600 {
		t.Errorf("opts = %+v", opts)
	}

	opts, err = parseTokenAddArgs([]string{
		"--url", "https://api.example.com/mcp",
		"--token-cmd", "gh auth token",
	})
	if err != nil {
		t.Fatalf("parseTokenAddArgs --token-cmd: %v", err)
	}
	if opts.tokenCmd != "gh auth token" {
		t.Errorf("tokenCmd = %q", opts.tokenCmd)
	}
}

func TestParseTokenAddRejectsBadInput(t *testing.T) {
	cases := map[string][]string{
		"no flags at all":      {},
		"missing --url":        {"--bearer", "tok"},
		"relative url":         {"--url", "/mcp", "--bearer", "tok"},
		"no token source":      {"--url", "https://api.example.com/mcp"},
		"bearer and token-cmd": {"--url", "https://api.example.com/mcp", "--bearer", "tok", "--token-cmd", "cmd"},
		"bearer and bearer-env": {"--url", "https://api.example.com/mcp", "--bearer", "tok",
			"--bearer-env", "MCPTUNNEL_TEST_TOKEN"},
		"refresh without token-url": {"--url", "https://api.example.com/mcp", "--bearer", "tok",
			"--refresh-token", "ref"},
		"token-url without refresh": {"--url", "https://api.example.com/mcp", "--bearer", "tok",
			"--token-url", "https://auth.example.com/token"},
		"refresh with token-cmd": {"--url", "https://api.example.com/mcp", "--token-cmd", "cmd",
			"--refresh-token", "ref", "--token-url", "https://auth.example.com/token"},
		"client-id without refresh": {"--url", "https://api.example.com/mcp", "--bearer", "tok",
			"--client-id", "c"},
		"positional arg": {"--url", "https://api.example.com/mcp", "--bearer", "tok", "extra"},
	}
	for name, args := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := parseTokenAddArgs(args); err == nil {
				t.Fatalf("parseTokenAddArgs(%q): want error, got nil", args)
			}
		})
	}
}

func TestParseTokenAddBearerEnv(t *testing.T) {
	t.Setenv("MCPTUNNEL_TEST_TOKEN", "tok-from-env")
	opts, err := parseTokenAddArgs([]string{
		"--url", "https://api.example.com/mcp",
		"--bearer-env", "MCPTUNNEL_TEST_TOKEN",
	})
	if err != nil {
		t.Fatalf("parseTokenAddArgs: %v", err)
	}
	if opts.bearer != "tok-from-env" {
		t.Errorf("bearer = %q", opts.bearer)
	}
	if _, err := parseTokenAddArgs([]string{
		"--url", "https://api.example.com/mcp",
		"--bearer-env", "MCPTUNNEL_TEST_TOKEN_UNSET",
	}); err == nil {
		t.Fatal("unset --bearer-env var: want error, got nil")
	}
}

func TestMask(t *testing.T) {
	if got := mask("abcdefghij"); got != "abc…ij" {
		t.Errorf("mask = %q", got)
	}
	if got := mask("short"); got != "…" {
		t.Errorf("short mask = %q", got)
	}
	if got := mask(""); got != "…" {
		t.Errorf("empty mask = %q", got)
	}
}

// tokenTransportFor consults the real default store; keep the URL unique
// enough that no registry entry can exist for it in the test environment.
func TestTokenTransportForExplicitHeaderWins(t *testing.T) {
	h := http.Header{"Authorization": {"Bearer explicit"}}
	if tr := tokenTransportFor("https://api.example.com/mcp", h); tr != nil {
		t.Errorf("explicit Authorization header must win over the registry; got %v", tr)
	}
}

func TestTokenTransportForNoEntry(t *testing.T) {
	if tr := tokenTransportFor("https://no-such-upstream.invalid/mcp", nil); tr != nil {
		t.Errorf("no registry entry: want nil transport, got %v", tr)
	}
	if tr := tokenTransportFor("", nil); tr != nil {
		t.Errorf("empty URL: want nil transport, got %v", tr)
	}
}
