package main

import "testing"

func TestParseRunHappyPath(t *testing.T) {
	opts, err := parseRunArgs([]string{
		"--url", "https://api.example.com/mcp",
		"--header", "Authorization: Bearer key",
		"--header", "X-Owner: yes",
	})
	if err != nil {
		t.Fatalf("parseRunArgs: %v", err)
	}
	if opts.upstreamURL != "https://api.example.com/mcp" {
		t.Errorf("upstreamURL = %q", opts.upstreamURL)
	}
	if got := opts.headers.Get("Authorization"); got != "Bearer key" {
		t.Errorf("Authorization = %q", got)
	}
	if got := opts.headers.Get("X-Owner"); got != "yes" {
		t.Errorf("X-Owner = %q", got)
	}
}

func TestParseRunRejectsBadInput(t *testing.T) {
	cases := map[string][]string{
		"no flags at all":   {},
		"missing --url":     {"--header", "Authorization: Bearer key"},
		"relative url":      {"--url", "/mcp"},
		"host-only url":     {"--url", "api.example.com/mcp"},
		"non-http scheme":   {"--url", "ftp://example.com/mcp"},
		"positional arg":    {"--url", "https://api.example.com/mcp", "extra"},
		"malformed header":  {"--url", "https://api.example.com/mcp", "--header", "nocolon"},
		"empty header name": {"--url", "https://api.example.com/mcp", "--header", ": v"},
	}
	for name, args := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := parseRunArgs(args); err == nil {
				t.Fatalf("parseRunArgs(%q): want error, got nil", args)
			}
		})
	}
}
