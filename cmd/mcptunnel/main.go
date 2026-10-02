// Command mcptunnel is the user-facing CLI for the mcptunnels quick-tunnel
// service (tunneld). `expose` runs a local stdio MCP server and exposes it
// through an anonymous, temporary public URL; `run` does the reverse, bridging
// a remote HTTP MCP endpoint to local stdio.
package main

import (
	"fmt"
	"io"
	"os"

	"github.com/terragohan/mcptunnels/internal/cli"
)

const usage = `usage: mcptunnel <command> [flags]

  expose   run a local stdio MCP server and expose it through tunneld at a
           temporary public URL (anonymous quick tunnel, expires in 24h)
  run      bridge a remote streamable-HTTP MCP endpoint to local stdio, so
           stdio-only MCP clients can use it (e.g. with --header credentials)
  token    manage the local bearer-token registry used by expose/run --url

mcptunnel expose [--server URL | --config PATH] [--no-auth] [--header "Name: value"]... (-- <mcp server command> [args...] | --url URL)
mcptunnel run --url URL [--header "Name: value"]...
mcptunnel token <add|list|remove> (run "mcptunnel token" for details)

  --server URL    tunneld base URL for expose (default: https://t-mcptunnels.terragohan.com, the hosted instance)
  --config PATH   tunneld.yaml to read the server URL from (same-host use)`

func main() {
	if err := run(os.Stdout, os.Args[1:]); err != nil {
		if ue, ok := err.(cli.UsageError); ok {
			fmt.Fprintln(os.Stderr, "mcptunnel:", ue.Err)
			os.Exit(2)
		}
		fmt.Fprintln(os.Stderr, "mcptunnel:", err)
		os.Exit(1)
	}
}

func run(w io.Writer, args []string) error {
	if len(args) < 1 {
		fmt.Fprintln(os.Stderr, usage)
		return cli.Usagef("no command given")
	}
	switch args[0] {
	case "expose":
		return runExpose(w, args[1:])
	case "run":
		return runRun(w, args[1:])
	case "token":
		return runToken(w, args[1:])
	case "-h", "--help", "help":
		fmt.Fprintln(w, usage)
		return nil
	default:
		return cli.Usagef("unknown command %q\n\n%s", args[0], usage)
	}
}
