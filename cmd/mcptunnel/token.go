package main

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"time"

	"github.com/terragohan/mcptunnels/internal/cli"
	"github.com/terragohan/mcptunnels/internal/tokencache"
)

const tokenUsage = `usage: mcptunnel token <command> [flags]

  mcptunnel token add --url URL --bearer TOKEN [--expires-in N]
  mcptunnel token add --url URL --bearer TOKEN --refresh-token R --token-url T [--client-id C]
  mcptunnel token add --url URL --token-cmd "gh auth token"
  mcptunnel token list
  mcptunnel token remove --url URL

Managed bearer tokens for HTTP MCP endpoints. Stored per-user under
$(os.UserConfigDir())/mcptunnels/tokens/ (0600) and used automatically by
expose --url and run --url. Precedence: an explicit --header
"Authorization: …" wins over a registry entry.

  --bearer-env NAME   read the bearer token from an environment variable
                      instead of --bearer (keeps it out of shell history)
  --expires-in N      seconds until the bearer expires (default: never)`

func runToken(w io.Writer, args []string) error {
	if len(args) < 1 {
		return cli.Usagef("no token command given\n\n%s", tokenUsage)
	}
	switch args[0] {
	case "add":
		return runTokenAdd(w, args[1:])
	case "list":
		return runTokenList(w, args[1:])
	case "remove":
		return runTokenRemove(w, args[1:])
	default:
		return cli.Usagef("unknown token command %q\n\n%s", args[0], tokenUsage)
	}
}

type tokenAddOpts struct {
	url          string
	bearer       string
	bearerEnv    string
	expiresIn    int64
	refreshToken string
	tokenURL     string
	clientID     string
	tokenCmd     string
}

// parseTokenAddArgs parses and validates `mcptunnel token add` flags.
func parseTokenAddArgs(args []string) (tokenAddOpts, error) {
	var opts tokenAddOpts
	fs := cli.NewFlagSet("token add")
	fs.StringVar(&opts.url, "url", "", "upstream URL this token is for")
	fs.StringVar(&opts.bearer, "bearer", "", "bearer token value")
	fs.StringVar(&opts.bearerEnv, "bearer-env", "", "environment variable to read the bearer token from")
	fs.Int64Var(&opts.expiresIn, "expires-in", 0, "seconds until the bearer expires (default: never)")
	fs.StringVar(&opts.refreshToken, "refresh-token", "", "refresh token for automatic renewal")
	fs.StringVar(&opts.tokenURL, "token-url", "", "token endpoint URL for the refresh grant")
	fs.StringVar(&opts.clientID, "client-id", "", "client_id sent with the refresh grant")
	fs.StringVar(&opts.tokenCmd, "token-cmd", "", "shell command that prints a fresh token (e.g. \"gh auth token\")")
	pos, err := cli.ParseIntermixed(fs, args)
	if err != nil {
		return tokenAddOpts{}, cli.Usagef("%v", err)
	}
	if len(pos) > 0 {
		return tokenAddOpts{}, cli.Usagef("unexpected argument %q", pos[0])
	}
	if opts.url == "" {
		return tokenAddOpts{}, cli.Usagef("--url is required\n\n%s", tokenUsage)
	}
	if _, err := tokencache.NormalizeURL(opts.url); err != nil {
		return tokenAddOpts{}, cli.Usagef("--url must be an absolute http(s) URL, got %q", opts.url)
	}
	if opts.bearer != "" && opts.bearerEnv != "" {
		return tokenAddOpts{}, cli.Usagef("--bearer and --bearer-env are mutually exclusive")
	}
	if opts.bearerEnv != "" {
		opts.bearer = os.Getenv(opts.bearerEnv)
		if opts.bearer == "" {
			return tokenAddOpts{}, cli.Usagef("environment variable %s is empty or unset", opts.bearerEnv)
		}
	}
	switch {
	case opts.tokenCmd != "" && opts.bearer != "":
		return tokenAddOpts{}, cli.Usagef("--token-cmd and --bearer are mutually exclusive")
	case opts.tokenCmd == "" && opts.bearer == "":
		return tokenAddOpts{}, cli.Usagef("one of --bearer (or --bearer-env) or --token-cmd is required\n\n%s", tokenUsage)
	case opts.refreshToken != "" && opts.tokenURL == "":
		return tokenAddOpts{}, cli.Usagef("--refresh-token requires --token-url")
	case opts.refreshToken != "" && opts.tokenCmd != "":
		return tokenAddOpts{}, cli.Usagef("--refresh-token cannot be combined with --token-cmd")
	case opts.tokenURL != "" && opts.refreshToken == "":
		return tokenAddOpts{}, cli.Usagef("--token-url requires --refresh-token")
	case opts.clientID != "" && opts.tokenURL == "":
		return tokenAddOpts{}, cli.Usagef("--client-id requires --refresh-token and --token-url")
	}
	return opts, nil
}

func runTokenAdd(w io.Writer, args []string) error {
	opts, err := parseTokenAddArgs(args)
	if err != nil {
		return err
	}
	e := &tokencache.Entry{
		URL:          opts.url,
		AccessToken:  opts.bearer,
		RefreshToken: opts.refreshToken,
		TokenURL:     opts.tokenURL,
		ClientID:     opts.clientID,
		TokenCmd:     opts.tokenCmd,
	}
	if opts.expiresIn > 0 {
		e.ExpiresAt = time.Now().Unix() + opts.expiresIn
	}
	if err := tokencache.DefaultStore().Save(e); err != nil {
		return err
	}
	fmt.Fprintf(w, "token stored for %s (%s)\n", opts.url, e.SourceType())
	return nil
}

func runTokenList(w io.Writer, args []string) error {
	fs := cli.NewFlagSet("token list")
	pos, err := cli.ParseIntermixed(fs, args)
	if err != nil {
		return cli.Usagef("%v", err)
	}
	if len(pos) > 0 {
		return cli.Usagef("unexpected argument %q", pos[0])
	}
	entries, err := tokencache.DefaultStore().List()
	if err != nil {
		return err
	}
	if len(entries) == 0 {
		fmt.Fprintln(w, "no tokens stored")
		return nil
	}
	for _, e := range entries {
		expiry := "never expires"
		switch {
		case e.ExpiresAt == 0:
		case time.Now().Unix() >= e.ExpiresAt:
			expiry = "expired " + time.Unix(e.ExpiresAt, 0).Format(time.RFC3339)
		default:
			expiry = "expires " + time.Unix(e.ExpiresAt, 0).Format(time.RFC3339)
		}
		fmt.Fprintf(w, "%s\n  token: %s  source: %s  %s\n", e.URL, mask(e.AccessToken), e.SourceType(), expiry)
	}
	return nil
}

// mask shows only the edges of a token: first 3 chars + "…" + last 2.
func mask(tok string) string {
	if len(tok) <= 5 {
		return "…"
	}
	return tok[:3] + "…" + tok[len(tok)-2:]
}

func runTokenRemove(w io.Writer, args []string) error {
	var rawURL string
	fs := cli.NewFlagSet("token remove")
	fs.StringVar(&rawURL, "url", "", "upstream URL whose token to remove")
	pos, err := cli.ParseIntermixed(fs, args)
	if err != nil {
		return cli.Usagef("%v", err)
	}
	if len(pos) > 0 {
		return cli.Usagef("unexpected argument %q", pos[0])
	}
	if rawURL == "" {
		return cli.Usagef("--url is required")
	}
	store := tokencache.DefaultStore()
	e, err := store.Lookup(rawURL)
	if err != nil {
		return err
	}
	if e == nil {
		return fmt.Errorf("no token stored for %s", rawURL)
	}
	if err := store.Remove(rawURL); err != nil {
		return err
	}
	fmt.Fprintf(w, "token removed for %s\n", rawURL)
	return nil
}

// tokenTransportFor returns a tokencache.Transport injecting the registry
// bearer token for upstreamURL, or nil when an explicit Authorization header
// was given (it wins) or no registry entry exists.
func tokenTransportFor(upstreamURL string, explicitHeaders http.Header) http.RoundTripper {
	if upstreamURL == "" {
		return nil
	}
	if explicitHeaders.Get("Authorization") != "" {
		return nil
	}
	store := tokencache.DefaultStore()
	e, err := store.Lookup(upstreamURL)
	if err != nil || e == nil {
		return nil
	}
	return &tokencache.Transport{Source: tokencache.NewSource(store, e)}
}
