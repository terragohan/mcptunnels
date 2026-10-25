package main

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"syscall"

	"github.com/terragohan/mcptunnels/internal/cli"
	"github.com/terragohan/mcptunnels/internal/stdiofront"
)

// runOpts is the parsed form of the `mcptunnel run` flags.
type runOpts struct {
	upstreamURL string
	headers     http.Header
}

// parseRunArgs parses and validates `mcptunnel run` flags. Usage problems
// come back as cli.UsageError.
func parseRunArgs(args []string) (runOpts, error) {
	opts := runOpts{headers: http.Header{}}
	fs := cli.NewFlagSet("run")
	fs.StringVar(&opts.upstreamURL, "url", "", "remote streamable-HTTP MCP endpoint to bridge to stdio")
	fs.Var(headerFlag(opts.headers), "header", "header to send to the upstream, \"Name: value\" (repeatable, e.g. an Authorization bearer token)")
	pos, err := cli.ParseIntermixed(fs, args)
	if err != nil {
		return runOpts{}, cli.Usagef("%v", err)
	}
	switch {
	case len(pos) > 0:
		return runOpts{}, cli.Usagef("unexpected argument %q", pos[0])
	case opts.upstreamURL == "":
		return runOpts{}, cli.Usagef("usage: mcptunnel run --url URL [--header \"Name: value\"]...")
	}
	u, err := url.Parse(opts.upstreamURL)
	if err != nil || u.Scheme == "" || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") {
		return runOpts{}, cli.Usagef("--url must be an absolute http(s) URL, got %q", opts.upstreamURL)
	}
	return opts, nil
}

// runRun implements `mcptunnel run --url URL`: bridge a remote streamable-HTTP
// MCP endpoint to stdio. The local MCP client talks JSON-RPC on stdin/stdout;
// everything the endpoint needs (session ids, bearer tokens via --header) is
// handled here. Ends on Ctrl-C or when the client closes stdin.
func runRun(w io.Writer, args []string) error {
	opts, err := parseRunArgs(args)
	if err != nil {
		return err
	}
	upstream, err := url.Parse(opts.upstreamURL)
	if err != nil {
		return err
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	fmt.Fprintf(os.Stderr, "mcptunnel run: bridging stdio to %s (Ctrl-C or close stdin to stop)\n", upstream)
	return stdiofront.Serve(ctx, os.Stdin, os.Stdout, upstream, opts.headers,
		tokenTransportFor(opts.upstreamURL, opts.headers))
}
