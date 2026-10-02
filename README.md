# mcptunnels

**Public URLs for local MCP servers in one command.** No signup, no config — tunnels are anonymous, OAuth-protected by default, and expire after 24 hours.

```sh
mcptunnel expose -- npx -y @modelcontextprotocol/server-everything
# → https://t-mcptunnels.terragohan.com/t/q-3k9x2mab7c/s/mcp
#   password: 9f2c1ab4e7d03815a6c02b94
```

Share the URL + password with your client or teammate. Works with Claude, ChatGPT, Cursor, or any remote MCP client.

![demo](assets/demo.gif)

> [!WARNING]
> `--no-auth` URLs are **fully public**: anyone with the link can call your tools, and all traffic transits the `tunneld` relay. Expose throwaway servers only — never private data. See [SECURITY.md](SECURITY.md).

## Install

### Prebuilt binary

Download the latest release for Linux/macOS (amd64/arm64) from [GitHub Releases](https://github.com/terragohan/mcptunnels/releases), extract the binary, and put it on your `PATH`:

```sh
# macOS example (Apple Silicon)
curl -L https://github.com/terragohan/mcptunnels/releases/latest/download/mcptunnel_darwin_arm64.tar.gz | tar xz
sudo mv mcptunnel /usr/local/bin/
```

### With Go

```sh
go install github.com/terragohan/mcptunnels/cmd/mcptunnel@latest
```

Requires Go 1.26+.

## Usage

One-liners (all against the hosted relay `https://t-mcptunnels.terragohan.com` unless `--server` is given):

```sh
mcptunnel expose -- npx -y @modelcontextprotocol/server-everything   # any stdio MCP server
mcptunnel expose --url https://api.example.com/mcp                   # an existing remote HTTP MCP server
mcptunnel expose --url https://api.example.com/mcp --header "Authorization: Bearer $KEY"   # with upstream credentials
mcptunnel expose --no-auth -- python3 my_mcp_server.py               # open URL, no OAuth
mcptunnel run --url https://api.example.com/mcp                      # use a remote HTTP MCP server from a stdio client
tunneld --config tunneld.yaml                                        # self-host the relay instead
```

In each case `expose` prints a public URL (and a password unless `--no-auth`) — plug the URL into your MCP client as a remote/streamable-HTTP server and you're done. Ctrl-C deletes the tunnel on the spot; otherwise it expires after 24h.

The general form — expose any stdio MCP server:

```sh
mcptunnel expose -- <mcp server command> [args...]
```

The CLI prints the public URL and a generated password. The client runs an OAuth flow and is asked for the password on the authorize page. To disable auth (not recommended):

```sh
mcptunnel expose --no-auth -- <mcp server command>
```

### Expose a remote HTTP MCP server

Instead of a local command, point the tunnel at an existing streamable-HTTP MCP server:

```sh
mcptunnel expose --url https://api.example.com/mcp
```

Clients append the upstream's base path to the public URL (e.g. `<public-url>/mcp`). The client's own `Authorization`/`Cookie` headers are stripped before forwarding; use `--header "Name: value"` (repeatable) to send credentials to the upstream:

```sh
mcptunnel expose --url https://api.example.com/mcp \
  --header "Authorization: Bearer $API_KEY"
```

### Use a remote HTTP MCP server from a stdio client

The reverse direction — `run` bridges a remote streamable-HTTP MCP endpoint to local stdio, so stdio-only clients can use it. Session ids, SSE responses, and server-initiated messages are handled; credentials go via `--header`:

```sh
mcptunnel run --url https://api.example.com/mcp \
  --header "Authorization: Bearer $API_KEY"
```

Point your client's stdio MCP config at `mcptunnel run …` as the command. It also composes with tunnels: `mcptunnel run --url <public tunnel URL>` pipes a remote tunneled server into a local stdio client.

### Managed bearer tokens (the registry)

For anything long-lived, don't put the secret in the command line — register it once per upstream and let mcptunnel refresh it automatically:

```sh
mcptunnel token add --url https://api.example.com/mcp --bearer-env API_KEY      # static token, from env
mcptunnel token add --url https://api.example.com/mcp --bearer TOKEN --refresh-token R --token-url https://auth.example.com/token   # auto-refresh
mcptunnel token add --url https://api.example.com/mcp --token-cmd "gh auth token"   # mint on demand from another CLI
mcptunnel token list        # what's registered (tokens masked)
mcptunnel token remove --url https://api.example.com/mcp
```

Then `mcptunnel expose --url https://api.example.com/mcp` (and `mcptunnel run --url …`) pick the token up automatically — no `--header` needed. Tokens live at 0600 in your OS config dir (`~/.config/mcptunnels/tokens/` on Linux, `~/Library/Application Support/mcptunnels/tokens/` on macOS). Precedence: an explicit `--header "Authorization: …"` beats the registry entry; with neither, requests go out unauthenticated.

Ctrl-C deletes the tunnel immediately. Otherwise it expires automatically after 24 hours.

### Connect a client

- **Claude Code**: `claude mcp add --transport http demo <url>`
- **ChatGPT / Cursor / others**: add the URL as a remote/streamable-HTTP MCP server and complete the OAuth flow using the printed password.

Then call a tool — that’s it.

## How it works

```
your machine                                  public host
┌──────────────────────┐    outbound WSS    ┌──────────────┐
│ mcp server (stdio)   │◀──────────────────│   tunneld    │◀── MCP client
│   ▲                  │   yamux streams    │  /t/q-*/mcp  │    (HTTPS)
│   └ bridge (loopback)│                    └──────────────┘
│   └ mcptunnel expose │  POST /api/v1/quick creates the tunnel
└──────────────────────┘
```

1. `expose` asks tunneld for a quick tunnel and gets an ephemeral tenant plus an agent key.
2. It spawns your command and bridges stdio to loopback HTTP.
3. The agent dials **outbound** to tunneld (WebSocket + yamux) — no inbound ports, works behind NAT.
4. tunneld reverse-proxies public requests over that connection.

Full details: [DESIGN.md](DESIGN.md).

## Development

One-liners (what CI runs):

```sh
make test   # go build + go test ./...
make lint   # go vet + gofmt check
make e2e    # binary-level end-to-end test: builds both binaries, boots a
            # real tunneld + fake MCP servers, checks tunneling, OAuth-less
            # and stdio modes, and Ctrl-C teardown
```

The full CI gate is:

```sh
go build ./... && go test ./... -count=1 && go vet ./... && test -z "$(gofmt -l .)"
```

To watch the end-to-end suites individually:

```sh
go test ./internal/server/ -v -count=1   # full OAuth user journey (in-process)
go test ./internal/proxy/ -v -count=1    # stdio MCP + remote-upstream suites
```

## License

[Apache 2.0](LICENSE). Security reports: [SECURITY.md](SECURITY.md).
