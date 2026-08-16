// Command mcptunnel is the user-facing CLI for the mcptunnels quick-tunnel
// service (tunneld). Its single command, expose, runs a local stdio MCP
// server and exposes it through an anonymous, temporary public URL.
package main

import (
	"fmt"
	"io"
	"os"

	"github.com/terragohan/mcptunnels/internal/cli"
)

const usage = `usage: mcptunnel expose [--server URL | --config PATH] -- <mcp server command> [args...]

Runs the given local stdio MCP server and exposes it through tunneld at a
temporary public URL (anonymous quick tunnel, expires in 24h; the URL is the
only secret — anyone who has it can use the server).

  --server URL    tunneld base URL (default: https://tunnel.mcptunnels.xyz, the hosted instance)
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
	case "-h", "--help", "help":
		fmt.Fprintln(w, usage)
		return nil
	default:
		return cli.Usagef("unknown command %q\n\n%s", args[0], usage)
	}
}
