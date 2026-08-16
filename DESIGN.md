# openai-tunnel-oauth — Multi-tenant Design (v2)

## 1. Problem (unchanged)

ChatGPT (Developer Mode connectors / Apps SDK) requires a publicly reachable
HTTPS MCP endpoint protected by OAuth 2.1 with PKCE and Dynamic Client
Registration. This service lets any backend MCP server connect out through a
tunnel and get a compliant, public, OAuth-protected URL without implementing
OAuth itself.

## 2. What changed from v1

- **Multi-tenant SaaS** — the operator hosts the service; tenants are created
  by an operator via CLI and get a permanent subpath: `https://host/t/{tenant}/…`.
- **No web app** — all sign-up, login, user/tenant/service management, audit
  viewing, and IdP configuration are done through the `mcptunnel` (users) and `mcptunnel-admin` (operators) CLIs.
- **One admin per tenant** — each tenant has a single CLI bearer token (no
  users, passwords, or email login for now).
- **Go only** — server, CLI, and agent are all Go.
- **SQLite (modernc.org/sqlite, pure Go)** — multi-tenant rows with
  `tenant_slug` isolation. The DB lives at `./data/tunneld.db`; persistence in
  k8s/docker-compose is just a volume on `./data`. PostgreSQL support is
  removed.

## 3. Architecture

```
tunneld (Go, single public process)
├── /t/{tenant}/*
│   ├── /authorize, /token, /register, /jwks.json   → per-tenant OAuth 2.1 AS
│   └── /s/{service}/mcp                            → public MCP endpoint
├── /api/v1/*                                       → control-plane API for mcptunnel
└── /healthz

mcptunnel (Go CLI)
  → calls /api/v1 with a bearer token (operator or tenant-admin)

tunnel-agent (Go)
  → dials outbound to wss://host/tunnel/connect
  → registers with tenant slug + service name + agent key
```

## 4. Tenancy model

- A **tenant** is identified by a permanent slug, chosen at creation:
  `https://host/t/{tenant}/…`. Slugs are permanent; renaming is not supported
  (URLs would break). Deletion is possible but destructive.
- Each tenant has **one admin CLI token** (generated at creation). The token is
  tied to the tenant and stored hashed in SQLite. It can be rotated; the old
  token is immediately revoked.
- There is a separate **operator CLI token** with global privileges (create /
  list / delete tenants, view any tenant’s audit log). It is created once via
  the bootstrap flow.

## 5. CLI authentication

`mcptunnel` authenticates to `/api/v1` with `Authorization: Bearer <token>`.

- **Operator token**: global. Created at bootstrap.
- **Tenant token**: scoped to one tenant. Returned by `mcptunnel signup` (invite-gated).

The CLI stores tokens in `~/.mcptunnel/session`:

```yaml
server: "https://tunnel.example.com"
token: "tun_ten_abc123..."
```

`mcptunnel login --server ... --token ...` writes this file. There is no
interactive login for tenants; the operator hands the tenant admin the token.

## 6. Public API surface

| Endpoint | Purpose |
|---|---|
| `/.well-known/oauth-protected-resource/t/{tenant}/s/{service}` | RFC 9728 resource metadata |
| `/.well-known/oauth-authorization-server/t/{tenant}` | RFC 8414 AS metadata |
| `/t/{tenant}/register` | DCR (open, rate-limited) |
| `/t/{tenant}/authorize` | OAuth authorize; per-tenant IdP broker |
| `/t/{tenant}/token` | OAuth token |
| `/t/{tenant}/jwks.json` | Tenant signing keys |
| `/t/{tenant}/s/{service}/mcp` | MCP proxy (token-gated) |
| `/api/v1/*` | Control plane (CLI-only) |
| `/tunnel/connect` | Agent WebSocket |
| `/healthz` | Health check |

ChatGPT sees a fully valid OAuth 2.1 AS per tenant. The tenant-scoped issuer is
`https://host/t/{tenant}`.

## 7. Control-plane API (CLI backend)

Base: `/api/v1`. All require `Authorization: Bearer`.

| Endpoint | Operator | Tenant admin |
|---|---|---|
| `POST /tenants` | ✅ create tenant, returns admin token | — |
| `GET /tenants` | ✅ list | — |
| `DELETE /tenants/{slug}` | ✅ destructive | — |
| `POST /tenants/{slug}/token/rotate` | ✅ | ✅ (own tenant only) |
| `POST /tenants/{slug}/services` | ✅ | ✅ |
| `GET /tenants/{slug}/services` | ✅ | ✅ |
| `DELETE /tenants/{slug}/services/{name}` | ✅ | ✅ |
| `POST /tenants/{slug}/services/{name}/agent-key` | ✅ | ✅ |
| `PUT /tenants/{slug}/idp` | ✅ | ✅ |
| `GET /tenants/{slug}/idp` | ✅ | ✅ |
| `DELETE /tenants/{slug}/idp` | ✅ | ✅ |
| `GET /tenants/{slug}/audit` | ✅ | ✅ |
| `POST /tenants/{slug}/keys/rotate` | ✅ | ✅ |
| `POST /tenants/{slug}/disable` | ✅ | ❌ |
| `POST /tenants/{slug}/enable` | ✅ | ❌ |

All mutation endpoints invalidate the per-tenant OAuth server cache, so IdP
changes, key rotations, and enable/disable take effect without a restart. A
disabled tenant's public endpoints under `/t/{slug}` return 404.

Bootstrap: `POST /api/v1/bootstrap` accepts a one-time setup token (printed by
tunneld on first run when no operator tokens exist) and returns an operator
token.

## 8. CLI commands (`mcptunnel`)

```sh
# one-time bootstrap
mcptunnel-admin bootstrap --server https://tunnel.example.com --setup-token <printed-by-tunneld>

# store a token locally
mcptunnel login --server https://tunnel.example.com --token <token>

# operator
mcptunnel-admin invite create               # mint a one-time signup code; users run mcptunnel signup
mcptunnel-admin tenant list
mcptunnel-admin tenant delete acme
mcptunnel-admin tenant disable acme               # operator-only; /t/acme returns 404
mcptunnel-admin tenant enable acme

# tenant admin (or operator)
mcptunnel token rotate                       # rotates the tenant token in session
mcptunnel service create acme/demo --auth-mode discovery_open
mcptunnel service list acme
mcptunnel service delete acme/demo
mcptunnel agent-key issue acme/demo          # prints the agent key
mcptunnel idp set acme --provider google --client-id ... --client-secret ... \
  --issuer https://accounts.google.com --allowed-domain acme.com
mcptunnel idp list acme
mcptunnel audit tail acme -n 50
mcptunnel keys rotate acme                   # rotate tenant signing key
```

## 9. Data model (SQLite)

```sql
tenants (
  slug TEXT PRIMARY KEY,
  display_name TEXT NOT NULL DEFAULT '',
  created_at INTEGER NOT NULL,
  disabled_at INTEGER
);

tenant_tokens (
  token_hash TEXT PRIMARY KEY,
  tenant_slug TEXT NOT NULL REFERENCES tenants(slug) ON DELETE CASCADE,
  created_at INTEGER NOT NULL,
  revoked_at INTEGER
);

operator_tokens (
  token_hash TEXT PRIMARY KEY,
  created_at INTEGER NOT NULL,
  revoked_at INTEGER
);

setup_tokens (
  token_hash TEXT PRIMARY KEY,
  created_at INTEGER NOT NULL
);

services (
  tenant_slug TEXT NOT NULL REFERENCES tenants(slug) ON DELETE CASCADE,
  name TEXT NOT NULL,
  agent_key_hash TEXT NOT NULL,
  identity_secret TEXT NOT NULL DEFAULT '',
  auth_mode TEXT NOT NULL DEFAULT 'strict',
  created_at INTEGER NOT NULL,
  PRIMARY KEY (tenant_slug, name)
);

idp_configs (
  tenant_slug TEXT NOT NULL REFERENCES tenants(slug) ON DELETE CASCADE,
  name TEXT NOT NULL,
  client_id TEXT NOT NULL,
  client_secret TEXT NOT NULL,
  issuer TEXT NOT NULL,
  allowed_emails TEXT NOT NULL DEFAULT '[]',
  allowed_domains TEXT NOT NULL DEFAULT '[]',
  created_at INTEGER NOT NULL,
  PRIMARY KEY (tenant_slug, name)
);

-- OAuth AS state is tenant-scoped
oauth_clients (
  tenant_slug TEXT NOT NULL REFERENCES tenants(slug) ON DELETE CASCADE,
  client_id TEXT NOT NULL,
  client_name TEXT NOT NULL DEFAULT '',
  redirect_uris TEXT NOT NULL,
  grant_types TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  PRIMARY KEY (tenant_slug, client_id)
);

auth_codes (
  tenant_slug TEXT NOT NULL REFERENCES tenants(slug) ON DELETE CASCADE,
  code TEXT NOT NULL,
  client_id TEXT NOT NULL,
  redirect_uri TEXT NOT NULL,
  code_challenge TEXT NOT NULL,
  scope TEXT NOT NULL DEFAULT '',
  resource TEXT NOT NULL DEFAULT '',
  subject TEXT NOT NULL,
  email TEXT NOT NULL DEFAULT '',
  expires_at INTEGER NOT NULL,
  used_at INTEGER,
  PRIMARY KEY (tenant_slug, code)
);

refresh_tokens (
  tenant_slug TEXT NOT NULL REFERENCES tenants(slug) ON DELETE CASCADE,
  token_hash TEXT NOT NULL,
  client_id TEXT NOT NULL,
  subject TEXT NOT NULL,
  email TEXT NOT NULL DEFAULT '',
  scope TEXT NOT NULL DEFAULT '',
  resource TEXT NOT NULL DEFAULT '',
  expires_at INTEGER NOT NULL,
  revoked_at INTEGER,
  rotated_to TEXT,
  PRIMARY KEY (tenant_slug, token_hash)
);

signing_keys (
  tenant_slug TEXT NOT NULL REFERENCES tenants(slug) ON DELETE CASCADE,
  kid TEXT NOT NULL,
  private_key TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  PRIMARY KEY (tenant_slug, kid)
);

audit_log (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  tenant_slug TEXT NOT NULL REFERENCES tenants(slug) ON DELETE CASCADE,
  ts INTEGER NOT NULL,
  event TEXT NOT NULL,
  subject TEXT NOT NULL DEFAULT '',
  client_id TEXT NOT NULL DEFAULT '',
  service TEXT NOT NULL DEFAULT '',
  ip TEXT NOT NULL DEFAULT '',
  detail TEXT NOT NULL DEFAULT '{}'
);
```

## 10. Agent protocol change

`tunnel-agent` connects to `/tunnel/connect` with:

- `Authorization: Bearer <agent_key>`
- `X-Tenant: acme`
- `X-Service-Name: demo`

The gateway validates the agent key against `services.agent_key_hash` for that
tenant, then multiplexes requests as before. All MCP traffic is scoped to
`/t/{tenant}/s/{service}/…`.

## 11. Security model

- CLI tokens are cryptographically random, stored hashed (bcrypt) in SQLite.
- Tenant tokens can only manage their own tenant; operator tokens are global.
- The public MCP endpoints are per-tenant OAuth 2.1 ASes; the backend MCP server
  still receives `X-Auth-*` identity headers (signed with the service
  `identity_secret`).
- `discovery_open` mode is per-service, same as v1.
- Tenant slugs are immutable after creation to avoid breaking public URLs.
- Audit log is tenant-scoped; operators see all.

## 12. Skill

A Kimi Code skill file documents the CLI for users:

```
.kimi/skills/mcptunnel.md
```

Contents: command reference, common setup flows, troubleshooting.

## 13. Migration from v1

v1 was single-tenant with root-path OAuth endpoints. v2 moves everything under
`/t/{tenant}/…`. This is a breaking change: existing single-tenant deployments
must create a tenant and update agent configs.

## 14. Milestones

- **M1** ✅ — SQLite store, tenant/operator token auth, `/api/v1` CRUD, CLI
  bootstrap + login + tenant/service commands.
- **M2** ✅ — Move public endpoints under `/t/{tenant}`, per-tenant OAuth AS,
  per-tenant signing keys, agent tenant slug in protocol.
- **M3** ✅ — Per-tenant IdP config via CLI, resolver cache invalidation so
  IdP changes take effect immediately.
- **M4** ✅ — Audit log CLI, key rotation, tenant enable/disable, hardening,
  Docker Compose with the ./data volume, `mcptunnel` skill.
