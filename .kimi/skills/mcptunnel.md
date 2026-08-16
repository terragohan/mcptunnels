---
name: mcptunnel
description: Expose local MCP servers through the openai-tunnel-oauth quick-tunnel service (tunneld) with `mcptunnel expose` — anonymous, ephemeral (24h) public URLs, no accounts. Use when deploying, configuring, or troubleshooting tunneld or tunnel connections.
---

# mcptunnel — quick-tunnel CLI

`mcptunnel` is the only user CLI, and `expose` is its only command. It talks
to tunneld's unauthenticated `POST /api/v1/quick` endpoint; all state lives
in tunneld's SQLite database. There are no accounts, sessions, or tokens.

## Usage

```sh
mcptunnel expose --server URL -- <mcp server command> [args...]
mcptunnel expose --config /path/to/tunneld.yaml -- <cmd>   # same-host: reads public_base_url
```

What it does, in one process:

1. POSTs `/api/v1/quick` → tunneld creates an ephemeral tenant (`q-<random>`,
   24h TTL) with one open service `mcp`, and returns an agent key
   (`tun_agent_...`, shown once, bcrypt-hashed at rest).
2. Spawns the stdio MCP server command and bridges it to loopback HTTP.
3. Connects the tunnel agent (outbound WebSocket to `/tunnel/connect`,
   authenticated with the agent key + `X-Tenant` / `X-Service-Name`).
4. Prints the public endpoint `<server>/t/<q-slug>/s/mcp/mcp`.

Flags: `--server URL` (tunneld base URL), `--config PATH` (read
`public_base_url` from a local tunneld.yaml). Ctrl-C stops everything;
`expose` exits if the MCP server exits.

## Server side (tunneld)

- Endpoints: `POST /api/v1/quick` (rate-limited 10/hour per remote IP),
  `GET /tunnel/connect` (agent gateway), `/t/{tenant}/s/{service}/...`
  (public open proxy — no auth, the URL is the secret), `GET /healthz`.
- Config (`tunneld.yaml`): `listen`, `public_base_url`, `tls.mode`
  (acme/manual/disabled), `database_path`. No other keys.
- A janitor deletes expired tenants every minute (cascade: services, agent
  keys).

## Troubleshooting

- `bad gateway: service offline` (502) — no agent currently connected for
  that (tenant, service); the expose process stopped or is reconnecting.
- 404 on a tunnel URL that worked before — the 24h TTL passed and the
  janitor deleted the tenant, or the URL is mistyped.
- 429 from `/api/v1/quick` — per-IP creation rate limit; retry within the
  hour or from another network.
