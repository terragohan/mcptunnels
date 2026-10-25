package main

import (
	"errors"
	"slices"
	"testing"

	"github.com/terragohan/mcptunnels/internal/cli"
)

func parseMust(t *testing.T, args ...string) exposeOpts {
	t.Helper()
	opts, err := parseExposeArgs(args)
	if err != nil {
		t.Fatalf("parseExposeArgs(%q): %v", args, err)
	}
	return opts
}

func parseWantErr(t *testing.T, args ...string) {
	t.Helper()
	_, err := parseExposeArgs(args)
	if err == nil {
		t.Fatalf("parseExposeArgs(%q): want error, got nil", args)
	}
	var ue cli.UsageError
	if !errors.As(err, &ue) {
		t.Fatalf("parseExposeArgs(%q): error %v is not a cli.UsageError", args, err)
	}
}

func TestParseStdioMode(t *testing.T) {
	opts := parseMust(t, "--no-auth", "--", "npx", "-y", "@modelcontextprotocol/server-everything")
	if !opts.noAuth {
		t.Error("noAuth = false; want true")
	}
	if opts.server != cli.DefaultServer {
		t.Errorf("server = %q; want default %q", opts.server, cli.DefaultServer)
	}
	if opts.upstreamURL != "" {
		t.Errorf("upstreamURL = %q; want empty in stdio mode", opts.upstreamURL)
	}
	want := []string{"npx", "-y", "@modelcontextprotocol/server-everything"}
	if !slices.Equal(opts.cmdArgs, want) {
		t.Errorf("cmdArgs = %v; want %v", opts.cmdArgs, want)
	}
}

func TestParseURLMode(t *testing.T) {
	opts := parseMust(t,
		"--server", "https://tunnel.example.com",
		"--url", "https://api.example.com/mcp",
		"--header", "Authorization: Bearer key",
		"--header", "X-Owner: yes")
	if opts.server != "https://tunnel.example.com" {
		t.Errorf("server = %q", opts.server)
	}
	if opts.upstreamURL != "https://api.example.com/mcp" {
		t.Errorf("upstreamURL = %q", opts.upstreamURL)
	}
	if len(opts.cmdArgs) != 0 {
		t.Errorf("cmdArgs = %v; want empty in --url mode", opts.cmdArgs)
	}
	if got := opts.headers.Get("Authorization"); got != "Bearer key" {
		t.Errorf("Authorization header = %q", got)
	}
	if got := opts.headers.Get("X-Owner"); got != "yes" {
		t.Errorf("X-Owner header = %q", got)
	}
}

func TestParseRejectsBadCombinations(t *testing.T) {
	parseWantErr(t)                                                      // nothing at all
	parseWantErr(t, "--")                                                // -- but no command
	parseWantErr(t, "--url", "https://api.example.com/mcp", "--", "npx") // both modes
	parseWantErr(t, "npx", "--", "npx")                                  // positional before --
	parseWantErr(t, "--unknown-flag", "--", "npx")                       // bad flag
}

func TestParseRejectsBadURL(t *testing.T) {
	for _, u := range []string{"/mcp", "api.example.com/mcp", "ftp://example.com/mcp", "http://"} {
		parseWantErr(t, "--url", u)
	}
}

func TestParseRejectsBadHeader(t *testing.T) {
	parseWantErr(t, "--url", "https://api.example.com/mcp", "--header", "no-colon-here")
	parseWantErr(t, "--url", "https://api.example.com/mcp", "--header", ": empty-name")
}
