---
name: mcptunnel
description: Manage the multi-tenant openai-tunnel-oauth service (tunneld) via the mcptunnel (user) and mcptunnel-admin (operator) CLIs — signup, expose, services, agent keys, invites, tenants, per-tenant IdP, audit log, signing keys. Use when deploying, configuring, or troubleshooting tunneld tenants or tunnel-agent connections.
---

# mcptunnel — public CLI for the mcptunnels service

`mcptunnel` is the user-facing CLI: sign up, log in, and expose local MCP
servers through tunneld. It talks to the `/api/v1` HTTP API; all state lives
in tunneld's SQLite database. It stores its session (server URL + bearer
token) in `~/.mcptunnel/session` (mode 0600); mcptunnel-admin uses
`~/.mcptunnel/admin-session` so the operator credential never clobbers a user
session.

Token kinds:

- **Tenant admin token** — scoped to one tenant; what a user gets from
  `signup` via `signup`. Manages that tenant's
  services, agent keys, IdP config, audit log, signing keys.
- **Operator token** — global; creates invites/tenants, disables tenants,
  views any audit log. Created once via `bootstrap` (operator only).
- **Invite codes** (`mcp_invite_...`) — one-time codes gating public signup;
  minted by operators with `mcptunnel-admin invite create`.

Every command accepts `--server` / `--token` to override the session file, and
`--config PATH` to read the server URL from a local `tunneld.yaml`
(`public_base_url`) when running on the same host as tunneld.

## Command reference

```sh
# Users
mcptunnel signup <slug> --server URL --invite CODE [--display-name X]
                                                     # creates the tenant, saves the session,
                                                     # prints the login password (mcp_pass_..., shown once)
mcptunnel login --server URL --token TOK             # store a token locally
mcptunnel expose <tenant>/<name> [--auth-mode strict|discovery_open] -- <cmd> [args...]

# Operator only
mcptunnel-admin bootstrap --server URL --setup-token TOK   # one-time; setup token is printed by tunneld on first run
mcptunnel-admin invite create                              # mint a one-time signup code
mcptunnel-admin tenant list                                # slug, display name, status, created
mcptunnel-admin tenant disable <slug>                      # public /t/<slug>/... endpoints start returning 404
mcptunnel-admin tenant enable <slug>
mcptunnel-admin tenant delete <slug>                       # destructive: cascades tokens, services, IdPs, OAuth state

# Tenant admin (or operator)
mcptunnel token rotate --tenant <slug>               # revokes old token immediately; updates session file
mcptunnel password reset <tenant>                    # new OAuth login password; old one dies; shown once
mcptunnel service create <tenant>/<name> [--auth-mode strict|discovery_open] [--identity-secret S]
                                                     # prints the agent key (tun_agent_...)
mcptunnel service list <tenant>
mcptunnel service delete <tenant>/<name>
mcptunnel agent-key issue <tenant>/<name>            # rotate + print a new agent key; old key dies
mcptunnel idp set <tenant> --provider NAME --client-id ID --client-secret SECRET \
    --issuer URL [--allowed-domain D ...] [--allowed-email E ...]
mcptunnel idp list <tenant>
mcptunnel idp delete <tenant> --provider NAME
mcptunnel audit tail <tenant> [-n 50]
mcptunnel keys rotate <tenant>                       # new ES256 signing key; outstanding access tokens die

# Expose a stdio MCP server in one command (ngrok-style)
mcptunnel expose <tenant>/<name> [--auth-mode strict|discovery_open] -- <cmd> [args...]
                                                     # spawns the MCP server command, bridges stdio→HTTP,
                                                     # connects the agent; creates the service if needed and
                                                     # issues a fresh agent key each run (old keys die).
                                                     # Prints the public URL; exits if the MCP process exits.
```

Slugs are permanent and lowercase `[a-z0-9-]`; a tenant's public base is
`https://<host>/t/<slug>`.

## Common setups

### First deployment from scratch

```sh
# 1. Start tunneld; on first run it logs a setup token AND writes it to
#    <database dir>/setup_token (mode 0600, deleted once bootstrap succeeds):
#    WARN tunneld: no operator tokens exist ... setup_token=tun_setup_...
# 2. Bootstrap (writes ~/.mcptunnel/session with the operator token):
mcptunnel-admin bootstrap --server https://tunnel.example.com --setup-token tun_setup_...
# 3. Mint an invite; the user signs up and creates a service:
mcptunnel-admin invite create                          # → one-time code (mcp_invite_...)
#    (user side, their machine)
mcptunnel signup acme --server https://tunnel.example.com --invite mcp_invite_...
mcptunnel service create acme/demo --identity-secret "$(openssl rand -hex 32)"
#    → agent key (tun_agent_...)
# 4. On the MCP server's host, write agent.yaml:
#      server: "wss://tunnel.example.com"
#      tenant: "acme"
#      service: "demo"
#      agent_key: "tun_agent_..."
#      upstream: "http://localhost:3000"
#    and start tunnel-agent.
# 5. In ChatGPT: connector URL https://tunnel.example.com/t/acme/s/demo/mcp,
#    auth: OAuth. ChatGPT does DCR + PKCE itself; the browser login uses the
#    tenant's IdP, or the tenant login password (issued at signup) when no IdP is configured.
```

### Adding a new MCP server to an existing tenant

```sh
mcptunnel login --server https://tunnel.example.com --token tun_ten_...   # tenant admin token
mcptunnel expose acme/billing -- npx -y @my/mcp-server    # one step: spawns, bridges, connects
# or, for an HTTP upstream / long-running separate agent:
mcptunnel service create acme/billing --auth-mode strict
# deploy a second agent with service: "billing" and the new agent key
```

### Configuring Google sign-in for a tenant

1. Google Cloud Console → Credentials → OAuth client ID (Web application).
2. Authorized redirect URI: `https://<host>/t/<tenant>/idp/google/callback`.
3. ```sh
   mcptunnel idp set acme --provider google \
     --client-id "....apps.googleusercontent.com" --client-secret "GOCSPX-..." \
     --issuer https://accounts.google.com --allowed-domain yourcompany.com
   ```
   Takes effect immediately (no tunneld restart). With exactly one provider,
   `/authorize` auto-redirects to it; with several, users get a picker.

## Troubleshooting

- **agent connect fails with 401** — the agent key doesn't match the
  (tenant, service). Keys are bcrypt-hashed in the store; plaintext is only
  shown at creation. Re-issue: `mcptunnel agent-key issue acme/demo` and update
  `agent.yaml`. Check `tenant`/`service` in agent.yaml match exactly.
- **401 on the public MCP endpoint with a bearer token** — tokens are
  tenant-scoped: `iss` must be `https://host/t/<tenant>` and `aud` must cover
  the resource URL. A token from tenant A never works on tenant B. Fetch
  `/.well-known/oauth-protected-resource/t/<tenant>/s/<service>` to see the
  expected authorization server.
- **"invalid token" right after `token rotate` or `keys rotate`** — expected:
  rotation revokes immediately. `token rotate` updates `~/.mcptunnel/session`
  automatically; if you rotated with `--token` override, `login` again.
  `keys rotate` invalidates outstanding *access* tokens (15 min TTL); clients
  just use their refresh token.
- **`bootstrap` returns "bootstrap already completed"** — an operator token
  already exists. Use `login` with an existing token. There is no recovery
  path for a lost operator token besides direct DB access.
- **tenant public endpoints 404 but control plane works** — the tenant is
  disabled (`mcptunnel-admin tenant list` shows `disabled`); `mcptunnel-admin tenant enable <slug>`.
- **ChatGPT scanner hangs before OAuth** — set the service to
  `--auth-mode discovery_open` (unauthenticated initialize/ping/tools/list on
  `/mcp` only; `tools/call` still requires a token).
- **IdP change not visible** — it is live immediately; if a user is mid-login
  they may hold state from the old config. Re-check `mcptunnel idp list <tenant>`.
