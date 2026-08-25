# mcptunnels

**Public URLs for local MCP servers in one command.** No signup, no config — tunnels are anonymous, OAuth-protected by default, and expire after 24 hours.

```sh
mcptunnel expose -- npx -y @modelcontextprotocol/server-everything
# → https://tunnel.mcptunnels.xyz/t/q-3k9x2mab7c/s/mcp
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

Expose any stdio MCP server to the hosted relay (default `https://tunnel.mcptunnels.xyz`):

```sh
mcptunnel expose -- <mcp server command> [args...]
```

Example:

```sh
mcptunnel expose -- npx -y @modelcontextprotocol/server-everything
```

The CLI prints the public URL and a generated password. The client runs an OAuth flow and is asked for the password on the authorize page. To disable auth (not recommended):

```sh
mcptunnel expose --no-auth -- <mcp server command>
```

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

```sh
go build ./...
go test ./... -count=1
go vet ./...
gofmt -l .   # must be empty
```

## License

[Apache 2.0](LICENSE). Security reports: [SECURITY.md](SECURITY.md).
