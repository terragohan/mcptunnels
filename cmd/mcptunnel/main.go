// Command mcptunnel is the public, user-facing CLI for the mcptunnels
// service (tunneld): sign up with an invite code, log in, and expose local
// MCP servers. Operator functions (bootstrap, invites, tenant management)
// live in the separate mcptunnel-admin binary.
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

// sessionPath is resolved in main from the user's home dir.
var sessionPath string

const usage = `usage: mcptunnel <command> [flags]

Getting started:
  signup <slug> (--server URL | --config PATH) --invite CODE [--display-name X]
                                             create your account with an invite code;
                                             saves the session automatically
  login (--server URL | --config PATH) --token TOK
                                             store a token locally
  expose <tenant>/<name> [--auth-mode strict|discovery_open] -- <cmd> [args...]
                                             run a local stdio MCP server command and expose it
                                             through the tunnel in one step (creates the service
                                             if needed; issues a fresh agent key)

Services:
  service create <tenant>/<name> [--auth-mode strict|discovery_open] [--identity-secret S]
  service list <tenant>
  service delete <tenant>/<name>
  agent-key issue <tenant>/<name>            rotate and print the agent key

Account:
  token rotate --tenant SLUG                 rotate your tenant token; updates the session file
  password reset <tenant>                    new login password (old one dies); shown once
  idp set <tenant> --provider NAME --client-id ID --client-secret SECRET \
      --issuer URL [--allowed-domain D ...] [--allowed-email E ...]
  idp list <tenant>
  idp delete <tenant> --provider NAME
  audit tail <tenant> [-n 50]
  keys rotate <tenant>                       new signing key; outstanding access tokens die

Most commands accept --server/--token/--config to override the session file
(~/.mcptunnel/session).`

func main() {
	var err error
	sessionPath, err = cli.DefaultSessionPath()
	if err != nil {
		fmt.Fprintln(os.Stderr, "mcptunnel:", err)
		os.Exit(1)
	}
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
	case "signup":
		return runSignup(w, args[1:])
	case "login":
		return runLogin(w, args[1:])
	case "expose":
		return runExpose(w, args[1:])
	case "token":
		return runToken(w, args[1:])
	case "password":
		return runPassword(w, args[1:])
	case "service":
		return runService(w, args[1:])
	case "agent-key":
		return runAgentKey(w, args[1:])
	case "idp":
		return runIDP(w, args[1:])
	case "audit":
		return runAudit(w, args[1:])
	case "keys":
		return runKeys(w, args[1:])
	case "-h", "--help", "help":
		fmt.Fprintln(w, usage)
		return nil
	default:
		return cli.Usagef("unknown command %q", args[0])
	}
}

// runSignup implements `mcptunnel signup <slug> --invite CODE`: public
// invite-gated self-service account creation. The returned tenant token is
// saved as the session, so the user can go straight to `expose`.
func runSignup(w io.Writer, args []string) error {
	fs := cli.NewFlagSet("signup")
	server := fs.String("server", "", "server URL (required unless --config is given)")
	configPath := fs.String("config", "", "tunneld.yaml to read the server URL from (same-host use)")
	invite := fs.String("invite", "", "invite code (required)")
	displayName := fs.String("display-name", "", "human-readable name")
	pos, err := cli.ParseIntermixed(fs, args)
	if err != nil {
		return cli.Usagef("%v", err)
	}
	if *server == "" && *configPath != "" {
		s, err := cli.ServerFromConfig(*configPath)
		if err != nil {
			return err
		}
		*server = s
	}
	if len(pos) != 1 || *server == "" || *invite == "" {
		return cli.Usagef("usage: mcptunnel signup <slug> (--server URL | --config PATH) --invite CODE [--display-name X]")
	}
	c := cli.NewClient(*server, "")
	var resp struct {
		Slug     string `json:"slug"`
		Token    string `json:"token"`
		Password string `json:"password"`
	}
	if err := c.Do("POST", "/signup", nil, map[string]string{
		"slug":         pos[0],
		"display_name": *displayName,
		"invite":       *invite,
	}, &resp); err != nil {
		return err
	}
	if err := cli.SaveSession(sessionPath, &cli.Session{Server: *server, Token: resp.Token}); err != nil {
		return err
	}
	fmt.Fprintf(w, "welcome! tenant %q created and session saved.\n\nyour login password (shown once; used when connecting MCP clients):\n\n  %s\n\nexpose your first MCP server:\n\n  mcptunnel expose %s/<name> -- <mcp server command>\n", resp.Slug, resp.Password, resp.Slug)
	return nil
}

func runLogin(w io.Writer, args []string) error {
	fs := cli.NewFlagSet("login")
	server := fs.String("server", "", "server URL (required unless --config is given)")
	token := fs.String("token", "", "bearer token (required)")
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
	if *server == "" || *token == "" {
		return cli.Usagef("usage: mcptunnel login (--server URL | --config PATH) --token TOK")
	}
	if err := cli.SaveSession(sessionPath, &cli.Session{Server: *server, Token: *token}); err != nil {
		return err
	}
	fmt.Fprintf(w, "session written; logged in to %s\n", *server)
	return nil
}

func runToken(w io.Writer, args []string) error {
	if len(args) < 1 || args[0] != "rotate" {
		return cli.Usagef("usage: mcptunnel token rotate --tenant SLUG")
	}
	fs := cli.NewFlagSet("token rotate")
	var conn cli.ConnFlags
	conn.Register(fs)
	tenant := fs.String("tenant", "", "tenant slug to rotate")
	if _, err := cli.ParseIntermixed(fs, args[1:]); err != nil {
		return cli.Usagef("%v", err)
	}
	c, err := conn.Resolve(sessionPath)
	if err != nil {
		return err
	}
	slug := *tenant
	if slug == "" {
		return cli.Usagef("usage: mcptunnel token rotate --tenant SLUG (the session token is scoped to a tenant, but the slug is not stored locally)")
	}
	var resp struct {
		Token string `json:"token"`
	}
	if err := c.Do("POST", "/tenants/"+url.PathEscape(slug)+"/token/rotate", nil, nil, &resp); err != nil {
		return err
	}
	// If the session token was used (no --token override), update the session
	// file with the new token.
	if conn.Token == "" {
		if s, err := cli.LoadSession(sessionPath); err == nil {
			s.Token = resp.Token
			if err := cli.SaveSession(sessionPath, s); err != nil {
				fmt.Fprintf(os.Stderr, "warning: could not update session file: %v\n", err)
			}
		}
	}
	fmt.Fprintf(w, "rotated token for tenant %s; new token (store it safely, it cannot be recovered):\n\n  %s\n", slug, resp.Token)
	return nil
}

// runPassword implements `mcptunnel password reset <tenant>`: issues a new
// OAuth login password, replacing the old one.
func runPassword(w io.Writer, args []string) error {
	if len(args) < 1 || args[0] != "reset" {
		return cli.Usagef("usage: mcptunnel password reset <tenant>")
	}
	fs := cli.NewFlagSet("password reset")
	var conn cli.ConnFlags
	conn.Register(fs)
	pos, err := cli.ParseIntermixed(fs, args[1:])
	if err != nil {
		return cli.Usagef("%v", err)
	}
	if len(pos) != 1 {
		return cli.Usagef("usage: mcptunnel password reset <tenant>")
	}
	c, err := conn.Resolve(sessionPath)
	if err != nil {
		return err
	}
	var resp struct {
		Password string `json:"password"`
	}
	if err := c.Do("POST", "/tenants/"+url.PathEscape(pos[0])+"/password", nil, nil, &resp); err != nil {
		return err
	}
	fmt.Fprintf(w, "new login password for tenant %s (the old one no longer works; shown once):\n\n  %s\n", pos[0], resp.Password)
	return nil
}

func runService(w io.Writer, args []string) error {
	if len(args) < 1 {
		return cli.Usagef("usage: mcptunnel service create|list|delete ...")
	}
	switch args[0] {
	case "create":
		fs := cli.NewFlagSet("service create")
		var conn cli.ConnFlags
		conn.Register(fs)
		authMode := fs.String("auth-mode", "strict", "strict|discovery_open")
		identitySecret := fs.String("identity-secret", "", "upstream identity secret")
		pos, err := cli.ParseIntermixed(fs, args[1:])
		if err != nil {
			return cli.Usagef("%v", err)
		}
		if len(pos) != 1 {
			return cli.Usagef("usage: mcptunnel service create <tenant>/<name> [--auth-mode ...] [--identity-secret ...]")
		}
		tenant, name, err := cli.SplitRef(pos[0])
		if err != nil {
			return cli.Usagef("%v", err)
		}
		c, err := conn.Resolve(sessionPath)
		if err != nil {
			return err
		}
		var resp struct {
			Service  map[string]any `json:"service"`
			AgentKey string         `json:"agent_key"`
		}
		if err := c.Do("POST", "/tenants/"+url.PathEscape(tenant)+"/services", nil, map[string]string{
			"name":            name,
			"auth_mode":       *authMode,
			"identity_secret": *identitySecret,
		}, &resp); err != nil {
			return err
		}
		fmt.Fprintf(w, "created service %s/%s\n\nagent key (store it safely, it cannot be recovered):\n\n  %s\n", tenant, name, resp.AgentKey)
		return nil
	case "list":
		fs := cli.NewFlagSet("service list")
		var conn cli.ConnFlags
		conn.Register(fs)
		pos, err := cli.ParseIntermixed(fs, args[1:])
		if err != nil {
			return cli.Usagef("%v", err)
		}
		if len(pos) != 1 {
			return cli.Usagef("usage: mcptunnel service list <tenant>")
		}
		c, err := conn.Resolve(sessionPath)
		if err != nil {
			return err
		}
		var resp struct {
			Services []struct {
				Name      string `json:"name"`
				AuthMode  string `json:"auth_mode"`
				CreatedAt int64  `json:"created_at"`
			} `json:"services"`
		}
		if err := c.Do("GET", "/tenants/"+url.PathEscape(pos[0])+"/services", nil, nil, &resp); err != nil {
			return err
		}
		tw := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
		fmt.Fprintln(tw, "NAME\tAUTH_MODE\tCREATED")
		for _, s := range resp.Services {
			fmt.Fprintf(tw, "%s\t%s\t%s\n", s.Name, s.AuthMode, time.Unix(s.CreatedAt, 0).Format(time.RFC3339))
		}
		return tw.Flush()
	case "delete":
		fs := cli.NewFlagSet("service delete")
		var conn cli.ConnFlags
		conn.Register(fs)
		pos, err := cli.ParseIntermixed(fs, args[1:])
		if err != nil {
			return cli.Usagef("%v", err)
		}
		if len(pos) != 1 {
			return cli.Usagef("usage: mcptunnel service delete <tenant>/<name>")
		}
		tenant, name, err := cli.SplitRef(pos[0])
		if err != nil {
			return cli.Usagef("%v", err)
		}
		c, err := conn.Resolve(sessionPath)
		if err != nil {
			return err
		}
		if err := c.Do("DELETE", "/tenants/"+url.PathEscape(tenant)+"/services/"+url.PathEscape(name), nil, nil, nil); err != nil {
			return err
		}
		fmt.Fprintf(w, "deleted service %s/%s\n", tenant, name)
		return nil
	default:
		return cli.Usagef("unknown service subcommand %q", args[0])
	}
}

func runAgentKey(w io.Writer, args []string) error {
	if len(args) < 1 || args[0] != "issue" {
		return cli.Usagef("usage: mcptunnel agent-key issue <tenant>/<name>")
	}
	fs := cli.NewFlagSet("agent-key issue")
	var conn cli.ConnFlags
	conn.Register(fs)
	pos, err := cli.ParseIntermixed(fs, args[1:])
	if err != nil {
		return cli.Usagef("%v", err)
	}
	if len(pos) != 1 {
		return cli.Usagef("usage: mcptunnel agent-key issue <tenant>/<name>")
	}
	tenant, name, err := cli.SplitRef(pos[0])
	if err != nil {
		return cli.Usagef("%v", err)
	}
	c, err := conn.Resolve(sessionPath)
	if err != nil {
		return err
	}
	var resp struct {
		AgentKey string `json:"agent_key"`
	}
	if err := c.Do("POST", "/tenants/"+url.PathEscape(tenant)+"/services/"+url.PathEscape(name)+"/agent-key", nil, nil, &resp); err != nil {
		return err
	}
	fmt.Fprintf(w, "new agent key for %s/%s (store it safely, it cannot be recovered; the old key is revoked):\n\n  %s\n", tenant, name, resp.AgentKey)
	return nil
}

func runIDP(w io.Writer, args []string) error {
	if len(args) < 1 {
		return cli.Usagef("usage: mcptunnel idp set|list|delete ...")
	}
	switch args[0] {
	case "set":
		fs := cli.NewFlagSet("idp set")
		var conn cli.ConnFlags
		conn.Register(fs)
		provider := fs.String("provider", "", "provider name, e.g. google (required)")
		clientID := fs.String("client-id", "", "OIDC client ID (required)")
		clientSecret := fs.String("client-secret", "", "OIDC client secret (required)")
		issuer := fs.String("issuer", "", "OIDC issuer URL (required)")
		var allowedDomains, allowedEmails cli.StringSlice
		fs.Var(&allowedDomains, "allowed-domain", "allowed email domain (repeatable)")
		fs.Var(&allowedEmails, "allowed-email", "allowed email address (repeatable)")
		pos, err := cli.ParseIntermixed(fs, args[1:])
		if err != nil {
			return cli.Usagef("%v", err)
		}
		if len(pos) != 1 || *provider == "" || *clientID == "" || *clientSecret == "" || *issuer == "" {
			return cli.Usagef("usage: mcptunnel idp set <tenant> --provider NAME --client-id ID --client-secret SECRET --issuer URL [--allowed-domain D ...] [--allowed-email E ...]")
		}
		c, err := conn.Resolve(sessionPath)
		if err != nil {
			return err
		}
		if err := c.Do("PUT", "/tenants/"+url.PathEscape(pos[0])+"/idp", nil, map[string]any{
			"name":            *provider,
			"client_id":       *clientID,
			"client_secret":   *clientSecret,
			"issuer":          *issuer,
			"allowed_emails":  []string(allowedEmails),
			"allowed_domains": []string(allowedDomains),
		}, nil); err != nil {
			return err
		}
		fmt.Fprintf(w, "idp %q configured for tenant %s\n", *provider, pos[0])
		return nil
	case "list":
		fs := cli.NewFlagSet("idp list")
		var conn cli.ConnFlags
		conn.Register(fs)
		pos, err := cli.ParseIntermixed(fs, args[1:])
		if err != nil {
			return cli.Usagef("%v", err)
		}
		if len(pos) != 1 {
			return cli.Usagef("usage: mcptunnel idp list <tenant>")
		}
		c, err := conn.Resolve(sessionPath)
		if err != nil {
			return err
		}
		var resp struct {
			IDPs []struct {
				Name           string   `json:"name"`
				ClientID       string   `json:"client_id"`
				Issuer         string   `json:"issuer"`
				AllowedEmails  []string `json:"allowed_emails"`
				AllowedDomains []string `json:"allowed_domains"`
			} `json:"idps"`
		}
		if err := c.Do("GET", "/tenants/"+url.PathEscape(pos[0])+"/idp", nil, nil, &resp); err != nil {
			return err
		}
		tw := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
		fmt.Fprintln(tw, "NAME\tCLIENT_ID\tISSUER\tALLOWED_DOMAINS\tALLOWED_EMAILS")
		for _, i := range resp.IDPs {
			fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n", i.Name, i.ClientID, i.Issuer,
				cli.JoinComma(i.AllowedDomains), cli.JoinComma(i.AllowedEmails))
		}
		return tw.Flush()
	case "delete":
		fs := cli.NewFlagSet("idp delete")
		var conn cli.ConnFlags
		conn.Register(fs)
		provider := fs.String("provider", "", "provider name (required)")
		pos, err := cli.ParseIntermixed(fs, args[1:])
		if err != nil {
			return cli.Usagef("%v", err)
		}
		if len(pos) != 1 || *provider == "" {
			return cli.Usagef("usage: mcptunnel idp delete <tenant> --provider NAME")
		}
		c, err := conn.Resolve(sessionPath)
		if err != nil {
			return err
		}
		q := url.Values{"name": {*provider}}
		if err := c.Do("DELETE", "/tenants/"+url.PathEscape(pos[0])+"/idp", q, nil, nil); err != nil {
			return err
		}
		fmt.Fprintf(w, "deleted idp %q for tenant %s\n", *provider, pos[0])
		return nil
	default:
		return cli.Usagef("unknown idp subcommand %q", args[0])
	}
}

func runAudit(w io.Writer, args []string) error {
	if len(args) < 1 || args[0] != "tail" {
		return cli.Usagef("usage: mcptunnel audit tail <tenant> [-n 50]")
	}
	fs := cli.NewFlagSet("audit tail")
	var conn cli.ConnFlags
	conn.Register(fs)
	n := fs.Int("n", 50, "number of entries")
	pos, err := cli.ParseIntermixed(fs, args[1:])
	if err != nil {
		return cli.Usagef("%v", err)
	}
	if len(pos) != 1 {
		return cli.Usagef("usage: mcptunnel audit tail <tenant> [-n 50]")
	}
	c, err := conn.Resolve(sessionPath)
	if err != nil {
		return err
	}
	var resp struct {
		Entries []struct {
			TS       int64  `json:"ts"`
			Event    string `json:"event"`
			Subject  string `json:"subject"`
			ClientID string `json:"client_id"`
			Service  string `json:"service"`
			IP       string `json:"ip"`
			Detail   string `json:"detail"`
		} `json:"entries"`
	}
	q := url.Values{"n": {fmt.Sprint(*n)}}
	if err := c.Do("GET", "/tenants/"+url.PathEscape(pos[0])+"/audit", q, nil, &resp); err != nil {
		return err
	}
	for _, e := range resp.Entries {
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
			time.Unix(e.TS, 0).Format(time.RFC3339), e.Event, e.Subject, e.ClientID, e.Service, e.IP, e.Detail)
	}
	return nil
}

func runKeys(w io.Writer, args []string) error {
	if len(args) < 1 || args[0] != "rotate" {
		return cli.Usagef("usage: mcptunnel keys rotate <tenant>")
	}
	fs := cli.NewFlagSet("keys rotate")
	var conn cli.ConnFlags
	conn.Register(fs)
	pos, err := cli.ParseIntermixed(fs, args[1:])
	if err != nil {
		return cli.Usagef("%v", err)
	}
	if len(pos) != 1 {
		return cli.Usagef("usage: mcptunnel keys rotate <tenant>")
	}
	c, err := conn.Resolve(sessionPath)
	if err != nil {
		return err
	}
	var resp struct {
		KID  string `json:"kid"`
		Note string `json:"note"`
	}
	if err := c.Do("POST", "/tenants/"+url.PathEscape(pos[0])+"/keys/rotate", nil, nil, &resp); err != nil {
		return err
	}
	fmt.Fprintf(w, "rotated signing key for tenant %s\nkid: %s\n%s\n", pos[0], resp.KID, resp.Note)
	return nil
}
