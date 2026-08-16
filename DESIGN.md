# mcptunnels — Design (quick tunnels)

## 1. Problem

Expose a local stdio MCP server at a public HTTPS URL, with zero setup: no
account, no signup — like `ngrok http`, but for MCP. The URL is temporary
(24h). Public endpoints are OAuth 2.1-gated by default behind a random
password the CLI generates and prints (the authorize page asks for it);
`--no-auth` creates an open endpoint where the unguessable URL is the only
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
├── /t/{tenant}/authorize|token|register|jwks.json → per-tenant OAuth 2.1 AS
├── /.well-known/oauth-*/t/{tenant}/...            → RFC 8414 / RFC 9728 metadata
├── /t/{tenant}/s/{service}/...    → public MCP proxy (bearer-gated by default)
└── GET /healthz
```

There is no separate agent binary and no account system of any kind.

## 3. The quick-tunnel flow

1. `mcptunnel expose --server URL -- <cmd>` POSTs `/api/v1/quick` (no auth)
   with `{auth, password}` — unless `--no-auth`, the CLI generates a random
   24-hex-char password and sends it along.
2. tunneld creates an **ephemeral tenant** with a random slug
   `q-<10 chars from [a-z0-9]>` and `expires_at = now + 24h`, plus one
   service named `mcp`, and returns `{tenant, service, agent_key,
   expires_at}`. Only bcrypt hashes (agent key, password) are stored.
3. The CLI spawns `<cmd>`, bridges its stdio to a loopback HTTP server, and
   runs the tunnel agent in-process. The agent dials
   `wss://host/tunnel/connect` with `Authorization: Bearer <agent_key>` and
   `X-Tenant` / `X-Service-Name` headers; the gateway validates the key
   against the stored hash and registers a yamux session for the
   (tenant, service) pair.
4. tunneld prints nothing secret; the CLI prints the public endpoint
   `<server>/t/<q-slug>/s/mcp` and (unless `--no-auth`) the password.
5. Public requests to `/t/{tenant}/s/{service}/*` are reverse-proxied over
   the tunnel: the proxy resolves the service (404 if unknown), dials a yamux
   stream to the agent (502 if the agent is offline), and forwards the
   request to the loopback bridge, which translates HTTP back to stdio MCP.
6. When `expose` exits (Ctrl-C or the MCP server exits), it calls
   `DELETE /api/v1/quick/{tenant}` (agent-key auth) to destroy the tunnel
   immediately — URL, password, and all tokens die. A janitor in tunneld also
   deletes expired tenants every minute (cascading to services and agent
   keys); their URLs start returning 404 and their agent keys stop
   validating.

## 4. Threat model: URL-as-secret + OAuth

- Public MCP endpoints are **OAuth 2.1-gated by default**. Clients must
  complete the authorization-code flow to obtain a bearer token, and the
  authorize page requires the random password `expose` generated — so the URL
  alone is not enough. `--no-auth` creates an **unauthenticated** endpoint —
  anyone who learns `https://host/t/<q-slug>/s/mcp` can call the exposed
  server until the tunnel is stopped or expires.
- The underlying protection is unguessability (random slug + service path)
  plus the password. OAuth adds spec compliance (ChatGPT requires it), not
  real identity — there is no user login or account; one password per tunnel,
  known only to whoever ran `expose` and whoever they share it with.
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
(`./data/tunneld.db` by default). Tables:

- `tenants(slug, display_name, created_at, expires_at)` — all tenants are
  quick tunnels; `expires_at` is always set.
- `services(tenant_slug, name, agent_key_hash, auth_mode, password_hash,
  created_at)` — one `mcp` service per tenant; `password_hash` is the bcrypt
  hash of the CLI-generated authorize password (empty for `--no-auth`);
  cascades on tenant delete.
- `signing_keys(tenant_slug, private_key_pem, created_at)` — per-tenant ES256
  key for JWT signing; cascades on tenant delete.
- `oauth_clients(tenant_slug, client_id, redirect_uris, created_at)` — DCR
  registrations; cascades on tenant delete.
- `auth_codes(code_hash, tenant_slug, client_id, redirect_uri,
  code_challenge, expires_at, used_at)` — one-time authorization codes;
  cascades on tenant delete.

Databases created by older (account-based) versions keep their now-unused
tables/columns; tunneld simply never touches them — there are no destructive
migrations.

## 7. Configuration

`tunneld.yaml`: `listen`, `public_base_url` (used for the ACME allowlist and
by `mcptunnel expose --config` to find the server), `tls` (`acme` with
Let's Encrypt TLS-ALPN-01, `manual` cert/key, or `disabled` for local dev),
and `database_path` (or the `DATABASE_PATH` env var). Nothing else.
