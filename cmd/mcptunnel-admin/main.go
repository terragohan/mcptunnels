// Command mcptunnel-admin is the operator CLI for tunneld: one-time
// bootstrap, signup invite codes, and tenant lifecycle management. Users
// should get mcptunnel instead. It talks to the /api/v1 HTTP API with the
// operator token stored in ~/.mcptunnel/admin-session (kept separate from the
// user session so the two credentials never clobber each other).
package main

import (
	"fmt"
	"io"
	"net/url"
	"os"
	"text/tabwriter"
	"time"

	"github.com/generalpiston/openai-tunnel-oauth/internal/cli"
)

var sessionPath string

const usage = `usage: mcptunnel-admin <command> [flags]

Bootstrap:
  bootstrap (--server URL | --config PATH) --setup-token TOK
                                             one-time bootstrap; prints and stores the operator token

Signups:
  invite create                              mint a one-time signup invite code

Tenants (created by users via "mcptunnel signup"; there is no admin-side create):
  tenant list
  tenant disable <slug>                      block the tenant's public endpoints (404)
  tenant enable <slug>
  tenant delete <slug>                       destructive: cascades tokens, services, IdPs, OAuth state

Commands accept --server/--token/--config to override the session file
(~/.mcptunnel/admin-session).`

func main() {
	var err error
	sessionPath, err = cli.AdminSessionPath()
	if err != nil {
		fmt.Fprintln(os.Stderr, "mcptunnel-admin:", err)
		os.Exit(1)
	}
	if err := run(os.Stdout, os.Args[1:]); err != nil {
		if ue, ok := err.(cli.UsageError); ok {
			fmt.Fprintln(os.Stderr, "mcptunnel-admin:", ue.Err)
			os.Exit(2)
		}
		fmt.Fprintln(os.Stderr, "mcptunnel-admin:", err)
		os.Exit(1)
	}
}

func run(w io.Writer, args []string) error {
	if len(args) < 1 {
		fmt.Fprintln(os.Stderr, usage)
		return cli.Usagef("no command given")
	}
	switch args[0] {
	case "bootstrap":
		return runBootstrap(w, args[1:])
	case "invite":
		return runInvite(w, args[1:])
	case "tenant":
		return runTenant(w, args[1:])
	case "-h", "--help", "help":
		fmt.Fprintln(w, usage)
		return nil
	default:
		return cli.Usagef("unknown command %q", args[0])
	}
}

func runBootstrap(w io.Writer, args []string) error {
	fs := cli.NewFlagSet("bootstrap")
	server := fs.String("server", "", "server URL (required unless --config is given)")
	setupToken := fs.String("setup-token", "", "one-time setup token printed by tunneld (required)")
	configPath := fs.String("config", "", "tunneld.yaml to read the server URL from (same-host use)")
	if err := fs.Parse(args); err != nil {
		return cli.Usagef("%v", err)
	}
	if *server == "" && *configPath != "" {
		s, err := cli.ServerFromConfig(*configPath)
		if err != nil {
			return err
		}
		*server = s
	}
	if *server == "" || *setupToken == "" {
		return cli.Usagef("usage: mcptunnel-admin bootstrap (--server URL | --config PATH) --setup-token TOK")
	}
	c := cli.NewClient(*server, "")
	var resp struct {
		Token string `json:"token"`
	}
	if err := c.Do("POST", "/bootstrap", nil, map[string]string{"setup_token": *setupToken}, &resp); err != nil {
		return err
	}
	if err := cli.SaveSession(sessionPath, &cli.Session{Server: *server, Token: resp.Token}); err != nil {
		return err
	}
	fmt.Fprintf(w, "bootstrap complete; operator token (stored in %s):\n\n  %s\n", sessionPath, resp.Token)
	return nil
}

// runInvite implements `mcptunnel-admin invite create`.
func runInvite(w io.Writer, args []string) error {
	if len(args) < 1 || args[0] != "create" {
		return cli.Usagef("usage: mcptunnel-admin invite create")
	}
	fs := cli.NewFlagSet("invite create")
	var conn cli.ConnFlags
	conn.Register(fs)
	if _, err := cli.ParseIntermixed(fs, args[1:]); err != nil {
		return cli.Usagef("%v", err)
	}
	c, err := conn.Resolve(sessionPath)
	if err != nil {
		return err
	}
	var resp struct {
		Invite string `json:"invite"`
	}
	if err := c.Do("POST", "/invites", nil, nil, &resp); err != nil {
		return err
	}
	fmt.Fprintf(w, "invite code (one-time use):\n\n  %s\n", resp.Invite)
	return nil
}

func runTenant(w io.Writer, args []string) error {
	if len(args) < 1 {
		return cli.Usagef("usage: mcptunnel-admin tenant list|delete|disable|enable ...")
	}
	switch args[0] {
	case "list":
		fs := cli.NewFlagSet("tenant list")
		var conn cli.ConnFlags
		conn.Register(fs)
		if _, err := cli.ParseIntermixed(fs, args[1:]); err != nil {
			return cli.Usagef("%v", err)
		}
		c, err := conn.Resolve(sessionPath)
		if err != nil {
			return err
		}
		var resp struct {
			Tenants []struct {
				Slug        string `json:"slug"`
				DisplayName string `json:"display_name"`
				CreatedAt   int64  `json:"created_at"`
				DisabledAt  *int64 `json:"disabled_at"`
			} `json:"tenants"`
		}
		if err := c.Do("GET", "/tenants", nil, nil, &resp); err != nil {
			return err
		}
		tw := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
		fmt.Fprintln(tw, "SLUG\tDISPLAY_NAME\tSTATUS\tCREATED")
		for _, t := range resp.Tenants {
			status := "active"
			if t.DisabledAt != nil {
				status = "disabled"
			}
			fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", t.Slug, t.DisplayName, status, time.Unix(t.CreatedAt, 0).Format(time.RFC3339))
		}
		return tw.Flush()
	case "delete":
		fs := cli.NewFlagSet("tenant delete")
		var conn cli.ConnFlags
		conn.Register(fs)
		pos, err := cli.ParseIntermixed(fs, args[1:])
		if err != nil {
			return cli.Usagef("%v", err)
		}
		if len(pos) != 1 {
			return cli.Usagef("usage: mcptunnel-admin tenant delete <slug>")
		}
		c, err := conn.Resolve(sessionPath)
		if err != nil {
			return err
		}
		if err := c.Do("DELETE", "/tenants/"+url.PathEscape(pos[0]), nil, nil, nil); err != nil {
			return err
		}
		fmt.Fprintf(w, "deleted tenant %s\n", pos[0])
		return nil
	case "disable", "enable":
		verb := args[0]
		fs := cli.NewFlagSet("tenant " + verb)
		var conn cli.ConnFlags
		conn.Register(fs)
		pos, err := cli.ParseIntermixed(fs, args[1:])
		if err != nil {
			return cli.Usagef("%v", err)
		}
		if len(pos) != 1 {
			return cli.Usagef("usage: mcptunnel-admin tenant %s <slug>", verb)
		}
		c, err := conn.Resolve(sessionPath)
		if err != nil {
			return err
		}
		if err := c.Do("POST", "/tenants/"+url.PathEscape(pos[0])+"/"+verb, nil, nil, nil); err != nil {
			return err
		}
		fmt.Fprintf(w, "%sd tenant %s\n", verb, pos[0])
		return nil
	default:
		return cli.Usagef("unknown tenant subcommand %q", args[0])
	}
}
