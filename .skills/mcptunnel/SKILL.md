---
name: mcptunnel
description: Expose a local stdio MCP server at a public URL using the mcptunnels quick-tunnel service — anonymous, ephemeral (24h), no accounts. Use when the user wants to share an MCP server, make it reachable from a remote MCP client (Claude, ChatGPT, Cursor), or troubleshoot tunneld/tunnel connections.
---

# mcptunnel — quick-tunnel CLI

`mcptunnel` has one command: `expose`. It turns any local stdio MCP server
into a public Streamable HTTP endpoint via a `tunneld` server. No accounts,
no sessions — every tunnel is OAuth-gated behind a generated password and
expires after 24 hours (or when `expose` exits).

## Usage

```sh
mcptunnel expose [--no-auth] -- <mcp server command> [args...]
```

`--server` defaults to the hosted instance `https://tunnel.mcptunnels.xyz`;
pass `--server https://<tunneld-host>` to use another relay.

`--no-auth` disables OAuth on the public endpoint (anyone with the URL can
use it). By default the CLI generates a random password and the endpoint
requires an OAuth 2.1 bearer token — clients discover the flow automatically
and the authorize page asks for the password `expose` prints. Share the URL
and password together.

Example (expose the MCP reference server):

```sh
mcptunnel expose -- npx -y @modelcontextprotocol/server-everything
```

To expose an existing remote streamable-HTTP MCP server instead of a local
command, use `--url` (mutually exclusive with the command):

```sh
mcptunnel expose --url https://api.example.com/mcp \
  --header "Authorization: Bearer $API_KEY"
```

The client's own `Authorization`/`Cookie` headers are stripped before
forwarding; `--header "Name: value"` (repeatable) injects credentials for the
upstream. Clients reach the upstream under the public URL plus its base path
(e.g. `<public-url>/mcp`).

## Run: remote HTTP MCP server over local stdio

The reverse of `expose` — for stdio-only MCP clients that need to use a
remote streamable-HTTP MCP endpoint:

```sh
mcptunnel run --url https://api.example.com/mcp \
  --header "Authorization: Bearer $API_KEY"
```

The local client talks JSON-RPC on stdin/stdout; `run` handles session ids
(including transparent re-initialize on expiry), JSON or SSE responses, the
GET stream of server-initiated messages, and DELETE on shutdown. Ends on
Ctrl-C or when the client closes stdin. Put the command (with its flags) in
the client's stdio MCP configuration. Composes with tunnels:
`mcptunnel run --url <public tunnel URL>` uses a remote tunneled server.

## Token registry (managed bearer tokens)

For long-lived upstream credentials, register once per upstream URL instead of
passing `--header` every time:

```sh
mcptunnel token add --url https://api.example.com/mcp --bearer-env API_KEY                 # static, from env
mcptunnel token add --url https://api.example.com/mcp --bearer TOKEN \
  --refresh-token R --token-url https://auth.example.com/token                             # auto-refresh
mcptunnel token add --url https://api.example.com/mcp --token-cmd "gh auth token"          # mint on demand
mcptunnel token list && mcptunnel token remove --url https://api.example.com/mcp
```

Both `expose --url …` and `run --url …` look up the registry automatically
for the upstream URL. Tokens are stored 0600 in the OS config dir
(`~/.config/mcptunnels/tokens/` on Linux, `~/Library/Application Support/
mcptunnels/tokens/` on macOS). Precedence: explicit
`--header "Authorization: …"` > registry entry > no auth.

What happens, in one process:

1. POSTs `/api/v1/quick` (with the generated password, unless `--no-auth`) →
   tunneld creates an ephemeral tenant (`q-<random>`, 24h TTL) with one
   service (OAuth-gated by default) and returns an agent key.
2. Spawns the stdio MCP server command and bridges it to loopback HTTP (or,
   with `--url`, uses the remote URL directly as the upstream).
3. Connects the tunnel agent (outbound WebSocket to `/tunnel/connect`,
   authenticated with the agent key).
4. Prints the public endpoint (`<server>/t/<q-slug>/s/mcp`) and the password.

Leave the process running — Ctrl-C deletes the tunnel server-side
(`DELETE /api/v1/quick/{tenant}`, so URL and password die immediately), and
`expose` exits if the MCP server process exits. `--config
/path/to/tunneld.yaml` can replace `--server` on the same host (reads
`public_base_url`).

## Connecting MCP clients

Give the printed URL to the client as a remote/streamable-HTTP MCP server:

- **Claude Code**: `claude mcp add --transport http <name> <url>`
- **ChatGPT / other clients**: add the URL as a connector/MCP server; the
  client's OAuth flow opens the authorize page, which asks for the password
  from `expose` output. Never share URL+password publicly, and only expose
  throwaway servers, never private data.

## Server side (tunneld)

- Endpoints: `POST /api/v1/quick` (rate-limited 10/hour per remote IP),
  `DELETE /api/v1/quick/{tenant}` (agent-key auth, called by `expose` on
  exit), `GET /tunnel/connect` (agent gateway),
  `/t/{tenant}/s/{service}/...` (public proxy, OAuth+password-gated by
  default), `GET /healthz`.
- Config (`tunneld.yaml`): `listen`, `public_base_url`, `tls.mode`
  (acme/manual/disabled), `database_path`. No other keys; unknown keys fail
  startup.
- A janitor deletes expired tenants every minute.

## Troubleshooting

- `bad gateway: service offline` (502) — no agent connected for that tunnel;
  the expose process stopped or is reconnecting.
- 404 on a URL that worked before — `expose` was stopped (Ctrl-C deletes the
  tunnel) or the 24h TTL expired. Re-run `expose` for a fresh URL.
- 429 from `/api/v1/quick` — per-IP creation rate limit; wait or use another
  network.
- Client can't reach the URL — check TLS (production tunneld serves HTTPS on
  443 only; nothing listens on 80) and that the DNS record is not behind a
  proxy that strips paths.
