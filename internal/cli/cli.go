// Package cli holds the plumbing used by the mcptunnel CLI: the control-plane
// HTTP client and flag helpers.
package cli

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/terragohan/mcptunnels/internal/config"
)

// DefaultServer is the hosted tunneld instance used when --server is omitted.
const DefaultServer = "https://tunnel.mcptunnels.xyz"

// Client talks to the control-plane API under /api/v1.
type Client struct {
	Base string // server URL, no trailing slash
	hc   *http.Client
}

func NewClient(server string) *Client {
	return &Client{
		Base: strings.TrimRight(server, "/"),
		hc:   &http.Client{Timeout: 30 * time.Second},
	}
}

// Do performs one request. method/path/body as given; out is JSON-decoded if
// non-nil and the response has a body. Non-2xx responses become errors using
// the {"error": "..."} body when present.
func (c *Client) Do(method, path string, query url.Values, body, out any) error {
	u := c.Base + "/api/v1" + path
	if len(query) > 0 {
		u += "?" + query.Encode()
	}
	var rdr io.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			return err
		}
		rdr = bytes.NewReader(data)
	}
	req, err := http.NewRequest(method, u, rdr)
	if err != nil {
		return err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.hc.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		var e struct {
			Error string `json:"error"`
		}
		msg := http.StatusText(resp.StatusCode)
		if json.Unmarshal(data, &e) == nil && e.Error != "" {
			msg = e.Error
		}
		return fmt.Errorf("%s: %s", resp.Status, msg)
	}
	if out != nil && len(data) > 0 {
		if err := json.Unmarshal(data, out); err != nil {
			return fmt.Errorf("decoding response: %w", err)
		}
	}
	return nil
}

// ServerFromConfig reads the public_base_url from a tunneld config file.
func ServerFromConfig(path string) (string, error) {
	cfg, err := config.LoadDaemon(path)
	if err != nil {
		return "", err
	}
	return strings.TrimRight(cfg.PublicBaseURL, "/"), nil
}

// UsageError makes main exit with code 2 instead of 1.
type UsageError struct{ Err error }

func (UsageError) Error() string { return "usage error" }

func Usagef(format string, args ...any) error {
	return UsageError{Err: fmt.Errorf(format, args...)}
}

// NewFlagSet creates a FlagSet whose parse errors map to exit code 2.
func NewFlagSet(name string) *flag.FlagSet {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	return fs
}

// ParseIntermixed parses flags and positionals in any order (the std flag
// package alone stops at the first positional). It returns the positionals.
func ParseIntermixed(fs *flag.FlagSet, args []string) ([]string, error) {
	var positional []string
	for len(args) > 0 {
		if err := fs.Parse(args); err != nil {
			return nil, err
		}
		args = fs.Args()
		if len(args) == 0 {
			break
		}
		positional = append(positional, args[0])
		args = args[1:]
	}
	return positional, nil
}
