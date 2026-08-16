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

What happens, in one process:

1. POSTs `/api/v1/quick` (with the generated password, unless `--no-auth`) →
   tunneld creates an ephemeral tenant (`q-<random>`, 24h TTL) with one
   service (OAuth-gated by default) and returns an agent key.
2. Spawns the stdio MCP server command and bridges it to loopback HTTP.
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
