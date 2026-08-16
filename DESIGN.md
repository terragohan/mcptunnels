# openai-tunnel-oauth — Design (quick tunnels)

## 1. Problem

Expose a local stdio MCP server at a public HTTPS URL, with zero setup: no
account, no signup, no OAuth — like `ngrok http`, but for MCP. The URL is
temporary (24h) and unauthenticated; the unguessable URL itself is the only
secret.

## 2. Architecture

```
mcptunnel expose -- <cmd>          (user's machine, single process)
├── spawns the stdio MCP server command
├── bridge:   stdio MCP ⇄ HTTP on 127.0.0.1:<random>
└── agent:    dials OUTBOUND wss://host/tunnel/connect (agent key auth)

tunneld (Go, single public process)
├── POST /api/v1/quick             → creates the ephemeral tenant (unauthenticated)
├── GET  /tunnel/connect           → agent WebSocket gateway (agent-key auth)
├── /t/{tenant}/s/{service}/...    → public MCP proxy (open: no auth)
└── GET /healthz
```

There is no separate agent binary and no account system of any kind.

## 3. The quick-tunnel flow

1. `mcptunnel expose --server URL -- <cmd>` POSTs `/api/v1/quick` (no auth).
2. tunneld creates an **ephemeral tenant** with a random slug
   `q-<10 chars from [a-z0-9]>` and `expires_at = now + 24h`, plus one
   service named `mcp`, and returns `{tenant, service, agent_key,
   expires_at}`. Only the bcrypt hash of the agent key is stored.
3. The CLI spawns `<cmd>`, bridges its stdio to a loopback HTTP server, and
   runs the tunnel agent in-process. The agent dials
   `wss://host/tunnel/connect` with `Authorization: Bearer <agent_key>` and
   `X-Tenant` / `X-Service-Name` headers; the gateway validates the key
   against the stored hash and registers a yamux session for the
   (tenant, service) pair.
4. tunneld prints nothing secret; the CLI prints the public endpoint
   `<server>/t/<q-slug>/s/mcp/mcp`.
5. Public requests to `/t/{tenant}/s/{service}/*` are reverse-proxied over
   the tunnel: the proxy resolves the service (404 if unknown), dials a yamux
   stream to the agent (502 if the agent is offline), and forwards the
   request to the loopback bridge, which translates HTTP back to stdio MCP.
6. A janitor in tunneld deletes expired tenants every minute (cascading to
   services and agent keys); their URLs start returning 404 and their agent
   keys stop validating.

## 4. Threat model: URL-as-secret

- Public MCP endpoints are **unauthenticated by design**. Anyone who learns
  `https://host/t/<q-slug>/s/mcp/mcp` can call the exposed server until the
  tunnel expires or the user stops `expose`.
- The protection is unguessability: ~56 bits of random slug plus the service
  path. Users must treat the URL like a password and only expose throwaway /
  non-sensitive MCP servers.
- The **agent key** (`tun_agent_<48 hex>`) is the write side: only its bcrypt
  hash is stored, it is shown once by `expose`, and it dies with the tenant.
- TLS (ACME by default) protects both the agent WebSocket and public traffic
  in transit.

## 5. Abuse controls

Quick-tunnel creation is unauthenticated, so the only guard is a deliberate,
weak one: an in-memory per-remote-IP rate limit of 10 tunnels/hour (fixed
windows; a restart resets it). A distributed botnet walks right past it.
Mitigating factors: tunnels are ephemeral (24h max), carry no identity, hold
no data beyond the connected agent, and cost the operator only an SQLite row
plus an open WebSocket each. Operators who need more should put tunneld
behind a CDN/WAF rate limiter.

## 6. Storage

SQLite (modernc.org/sqlite, pure Go — no cgo), WAL mode, one file
(`./data/tunneld.db` by default). Two tables:

- `tenants(slug, display_name, created_at, expires_at)` — all tenants are
  quick tunnels; `expires_at` is always set.
- `services(tenant_slug, name, agent_key_hash, created_at)` — one `mcp`
  service per tenant; cascades on tenant delete.

Databases created by older (account-based) versions keep their now-unused
tables/columns; tunneld simply never touches them — there are no destructive
migrations.

## 7. Configuration

`tunneld.yaml`: `listen`, `public_base_url` (used for the ACME allowlist and
by `mcptunnel expose --config` to find the server), `tls` (`acme` with
Let's Encrypt TLS-ALPN-01, `manual` cert/key, or `disabled` for local dev),
and `database_path` (or the `DATABASE_PATH` env var). Nothing else.
