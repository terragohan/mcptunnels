# mcptunnels

**Give a local MCP server a public URL with one command.** No accounts, no
signup, no config files — tunnels are anonymous, expire after 24 hours, and
are OAuth 2.1-protected by default behind a generated password (`--no-auth`
for open URLs).

```sh
mcptunnel expose -- npx -y @modelcontextprotocol/server-everything
# → https://tunnel.mcptunnels.xyz/t/q-3k9x2mab7c/s/mcp
#   password: 9f2c1ab4e7d03815a6c02b94
```

Clients that run the OAuth flow are asked for the password once on the
authorize page; share it only with people you want using the tunnel.

Use it to connect ChatGPT, Claude, Cursor, or any remote MCP client to a
server running on your laptop; to demo an MCP server to a teammate; or to
test a server against a real client without deploying anything.

![demo](assets/demo.gif)

**Status: early beta.** The tunnel data plane is covered by end-to-end
tests; compatibility with every major hosted MCP client is not yet
exhaustively verified. Bug reports welcome. See [ROADMAP.md](ROADMAP.md) for
where the project is headed (permanent tunnels, MCP servers as scalable
HTTP services).

> [!WARNING]
> `--no-auth` tunnel URLs are **unauthenticated**: anyone who has the URL can
> call your server's tools, and all traffic transits the `tunneld` operator.
> Expose throwaway servers only — never private data. See
> [SECURITY.md](SECURITY.md).

## Where do I point `--server`?

`expose` needs a `tunneld` to tunnel through. It **defaults to the hosted
instance at `https://tunnel.mcptunnels.xyz`** — pass `--server` only to use
a different relay:

- **Just try it / share it now**: use the default. Nothing to run.
- **Run your own**: any cheap VPS with a domain (automatic HTTPS via ACME) —
  see [Self-hosting](#self-hosting) — then `--server https://your-host`.

## Install

Prebuilt binaries for Linux and macOS (amd64/arm64) are attached to each
[GitHub release](https://github.com/terragohan/mcptunnels/releases), along
with a `checksums_<os>_<arch>.txt` per platform — verify with
`shasum -a 256 -c checksums_<os>_<arch>.txt` before unpacking.

With Go 1.26+:

```sh
go install github.com/terragohan/mcptunnels/cmd/mcptunnel@latest
```

## Quickstart (fully local)

Terminal A — start tunneld (plain HTTP on :8484):

```sh
# from a clone:
go run ./cmd/tunneld -config ./tunneld.yaml

# or without cloning:
curl -sSL https://raw.githubusercontent.com/terragohan/mcptunnels/main/tunneld.yaml -o /tmp/tunneld.yaml
go run github.com/terragohan/mcptunnels/cmd/tunneld@latest -config /tmp/tunneld.yaml
```

Terminal B — expose any stdio MCP server:

```sh
mcptunnel expose --server http://localhost:8484 -- \
  npx -y @modelcontextprotocol/server-everything
```

`expose` prints the public endpoint and password, and holds the tunnel open:

```
http://localhost:8484/t/q-3k9x2mab7c/s/mcp

  password: 9f2c1ab4e7d03815a6c02b94
```

### Connect a client

- **Claude Code**: `claude mcp add --transport http demo <printed-url>`
- **ChatGPT / Cursor / others**: add the URL as a remote (streamable HTTP)
  MCP server. OAuth is on by default — clients discover it automatically and
  the authorize page asks for the printed password. Use `--no-auth` for a
  plain unauthenticated endpoint.

Then call a tool. That's the whole loop.

Ctrl-C stops everything: `expose` deletes the tunnel server-side (the URL
and password die immediately) and exits if the MCP server exits. After 24
hours the tunnel is deleted automatically if it is still around.

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

1. `expose` asks tunneld for a quick tunnel (`POST /api/v1/quick`, sending a
   generated password) and gets an ephemeral tenant (`q-*`, 24h TTL) plus a
   one-time agent key.
2. It spawns your command and bridges stdio to loopback HTTP.
3. The agent dials **outbound** to tunneld (WebSocket + yamux) — no inbound
   ports, works behind NAT.
4. tunneld reverse-proxies public requests over that connection.

Full details and threat model: [DESIGN.md](DESIGN.md).

## Why not ngrok / cloudflared?

Generic tunnels forward raw TCP/HTTP. mcptunnels is MCP-shaped.

|                           | mcptunnels | ngrok | cloudflared | bore  |
|---------------------------|------------|-------|-------------|-------|
| Takes an MCP server command | ✅        | ❌ (ports only) | ❌ | ❌ |
| stdio → Streamable HTTP bridging | ✅ | ❌ | ❌ | ❌ |
| No account required       | ✅         | ❌    | ❌ (for named tunnels) | ✅ |
| Self-hostable relay       | ✅         | ❌    | ❌          | ✅ |
| Ephemeral-by-default URLs | ✅ (24h TTL) | ❌  | ❌          | ✅ |

If you already have an MCP server listening on a port with its own HTTP
transport, a generic tunnel works fine. mcptunnels removes the stdio
bridging step and everything around it.

## FAQ

**Is there a hosted instance I can use?**
Yes — `https://tunnel.mcptunnels.xyz` is the default `--server`, so
`mcptunnel expose -- <cmd>` works out of the box. Run your own `tunneld`
(and pass `--server`) whenever you'd rather not trust a third-party relay.

**What happens after 24 hours?**
The tenant is deleted and the URL returns 404. Re-run `expose` for a fresh
URL. Ctrl-C does the same thing immediately.

**Can I get a stable/permanent URL?**
No — ephemeral URLs are the design. It keeps the service account-free and
limits the blast radius of a leaked URL. See DESIGN.md.

**Is my traffic encrypted?**
Client ↔ tunneld is TLS when tunneld runs with ACME or manual certs. But
the tunnel is not end-to-end encrypted: the tunneld operator can read every
payload. Don't tunnel secrets through a relay you don't control.

**Can I tunnel a non-MCP HTTP service?**
No. The CLI expects an MCP server command (stdio); the bridge speaks MCP.

**Does it work behind NAT / on a laptop that sleeps?**
NAT yes — the agent dials outbound. Sleeping closes the connection; the
agent reconnects on wake, and the same URL keeps working while the tenant
lives.

## Self-hosting

`tunneld` is a single static binary plus a SQLite file. Config
(`tunneld.yaml`) is four keys: `listen`, `public_base_url`, `tls` (acme /
manual / disabled), `database_path`. Unknown keys fail startup.

```sh
docker build --target tunneld -t mcptunnels/tunneld .   # or compose up -d
```

For a real deployment (automatic HTTPS via ACME on :443, supervisord on
Ubuntu 24.04), see `scripts/setup-ubuntu-24.04.sh`.

Endpoints:

- `POST /api/v1/quick` — create a tunnel (unauthenticated, 10/hour per IP,
  persisted in SQLite so a restart does not reset it; hard cap of 500 live
  tunnels, then 503).
- `DELETE /api/v1/quick/{tenant}` — destroy a tunnel early (agent-key auth;
  `expose` calls it on exit so the URL and password die with the process).
- `GET /tunnel/connect` — agent WebSocket, authenticated by the agent key.
- `/t/{tenant}/s/{service}/...` — the public proxy. OAuth-gated by default;
  the authorize page requires the password `expose` prints.
- `GET /healthz` — liveness.

Abuse takedown: kill a tenant instantly (over SSH, no HTTP endpoint) — its
public URL starts returning 404 and its agent key stops validating:

```sh
tunneld -config tunneld.yaml -kill-tenant q-3k9x2mab7c
```

## Development

```sh
go build ./...       # build
go test ./...        # tests (incl. in-process end-to-end tunnel tests)
go vet ./...         # CI also enforces gofmt
```

## License

[Apache 2.0](LICENSE). Security reports: see [SECURITY.md](SECURITY.md).
