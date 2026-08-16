# openai-tunnel-oauth

Self-hosted tunnel that lets ChatGPT reach local MCP servers. `tunneld` runs on a
public host; `tunnel-agent` runs next to a local MCP server and dials **outbound**
to `tunneld` (WebSocket + yamux), which reverse-proxies public HTTP requests over
that tunnel. `tunneld` also serves a complete OAuth 2.1 authorization server
(DCR, PKCE, rotating refresh tokens) so ChatGPT can connect; backend MCP servers
implement zero OAuth. See [DESIGN.md](DESIGN.md) for the full architecture.

## Quickstart (v2)

```sh
# 1. Terminal A — start tunneld (plain HTTP on :8484, tls.mode: disabled).
#    On first run it prints a one-time setup token.
go run ./cmd/tunneld -config ./tunneld.yaml

# 2. Bootstrap the operator account, mint an invite, and sign up a tenant.
go run ./cmd/mcptunnel-admin bootstrap --server http://localhost:8484 --setup-token <printed-by-tunneld>
go run ./cmd/mcptunnel-admin invite create              # prints a one-time invite code
go run ./cmd/mcptunnel signup acme --server http://localhost:8484 --invite <code>
go run ./cmd/mcptunnel service create acme/demo    # prints the agent key

# 3. Terminal B — start any local HTTP server on :3000 as the upstream
python3 -m http.server 3000

# 4. Terminal C — start the agent (tenant/service/agent_key in agent.yaml)
go run ./cmd/tunnel-agent -config ./agent.yaml
```

## One-command expose (stdio MCP servers)

If you're a **user** of a hosted instance (not the operator), the whole flow
is signup → expose:

```sh
mcptunnel signup <slug> --server https://tunnel.mcptunnels.xyz --invite <code>
mcptunnel expose <slug>/demo -- npx -y @modelcontextprotocol/server-everything
```

(Invite codes come from the operator: `mcptunnel-admin invite create`.)

If your MCP server is a stdio command (the common case), `expose` spawns it,
bridges it to HTTP locally, and connects the agent in one step — no agent.yaml:

```sh
go run ./cmd/mcptunnel login --server http://localhost:8484 --token <tenant admin token>
go run ./cmd/mcptunnel expose acme/demo -- npx -y @modelcontextprotocol/server-everything
```

`expose` creates the service if needed (pass `--auth-mode discovery_open` for
the ChatGPT scanner workaround), issues a fresh agent key, and prints the
public endpoint, e.g. `http://localhost:8484/t/acme/s/demo/mcp`. It exits if
the MCP server process exits; Ctrl-C stops everything. Each run rotates the
agent key, so a standalone `tunnel-agent` for the same service is kicked off.

## OAuth flow (per tenant)

Every tenant is a full OAuth 2.1 AS under `/t/{tenant}`; services live under
`/t/{tenant}/s/{service}`. Curl-level walkthrough:

```sh
BASE=http://localhost:8484
TEN=$BASE/t/acme

# Discovery (RFC 8414 / RFC 9728)
curl -s $BASE/.well-known/oauth-authorization-server/t/acme | jq
curl -s $BASE/.well-known/oauth-protected-resource/t/acme/s/demo | jq

# 1. Register a client (RFC 7591 DCR, open, rate-limited)
curl -s -X POST $TEN/register -H 'Content-Type: application/json' -d '{
  "redirect_uris": ["https://chatgpt.com/connector_platform_oauth_redirect"],
  "client_name": "curl-demo"
}' | jq          # → client_id

# 2. Authorize (normally done by a browser; the login page takes dev_auth.password)
#    GET $TEN/authorize?response_type=code&client_id=...&redirect_uri=...&state=...\
#        &code_challenge=<b64url(sha256(verifier))>&code_challenge_method=S256
#    → HTML login page → submit password → 302 redirect with ?code=...&state=...

# 3. Exchange the code
curl -s -X POST $TEN/token -d grant_type=authorization_code \
  -d client_id=... -d redirect_uri=... -d code=... -d code_verifier=... | jq
#   → access_token (ES256 JWT, 15m, iss=$TEN) + refresh_token (rotating)

# 4. Call the tunneled service
curl -i $TEN/s/demo/echo                                  # → 401 + WWW-Authenticate
curl -s $TEN/s/demo/ -H "Authorization: Bearer <access_token>"

# 5. Refresh (old refresh token is invalidated; reuse revokes the chain)
curl -s -X POST $TEN/token -d grant_type=refresh_token \
  -d client_id=... -d refresh_token=... | jq
```

With ChatGPT: create a Developer-Mode connector pointing at
`https://<your-host>/t/acme/s/demo/mcp` — ChatGPT performs steps 1–3 itself.
Real HTTPS is required (`tls.mode: acme` on a public host).

## Identity

`/t/{tenant}/authorize` has these identity modes per tenant:

- **Tenant login password** (default): each tenant gets its own password
  (`mcp_pass_...`), issued at `mcptunnel signup` and rotatable with
  `mcptunnel password reset <tenant>`. Tenants created before passwords
  existed fall back to the operator's global `dev_auth` password below.
- **OIDC providers** (per tenant, configured via `mcptunnel idp set`): real
  user identity brokered from any OIDC-compliant provider. `/authorize` shows
  a provider picker (or auto-redirects when exactly one provider is
  configured), runs an upstream authorization-code + PKCE flow, enforces
  optional `allowed_emails` / `allowed_domains` allowlists, and requires
  `email_verified` when the provider supplies it. The local subject becomes
  `{provider}:{upstream-sub}`.

Google setup example:

1. Google Cloud Console → APIs & Services → Credentials → Create OAuth client
   ID (Web application).
2. Authorized redirect URI: `https://<your-host>/t/acme/idp/google/callback`.
3. Configure the tenant (takes effect immediately — no restart needed):

   ```sh
   mcptunnel idp set acme --provider google \
     --client-id "....apps.googleusercontent.com" --client-secret "GOCSPX-..." \
     --issuer https://accounts.google.com --allowed-domain yourcompany.com
   ```

After authentication, both modes show a **consent screen** (client name,
requested scopes, the authenticated identity) with Approve/Deny; Deny
redirects with `access_denied` per RFC 6749.

### Identity headers for backends

When a service sets `identity_secret`, authenticated requests forwarded to
the backend carry:

- `X-Auth-Subject` — e.g. `google:104...`
- `X-Auth-Email`
- `X-Auth-Scopes` — space-separated
- `X-Auth-Client-Id`
- `X-Auth-Signature` — hex HMAC-SHA256 over
  `"{subject}\n{email}\n{scopes}\n{client_id}"` keyed with `identity_secret`

Verify in a backend (Go):

```go
mac := hmac.New(sha256.New, []byte(identitySecret))
mac.Write([]byte(strings.Join([]string{
    r.Header.Get("X-Auth-Subject"), r.Header.Get("X-Auth-Email"),
    r.Header.Get("X-Auth-Scopes"), r.Header.Get("X-Auth-Client-Id"),
}, "\n")))
expected := hex.EncodeToString(mac.Sum(nil))
if !hmac.Equal([]byte(expected), []byte(r.Header.Get("X-Auth-Signature"))) {
    http.Error(w, "bad signature", http.StatusUnauthorized)
    return
}
```

### discovery_open auth mode

Per service: `auth_mode: strict` (default) or `discovery_open`. ChatGPT's
connector scanner enumerates tools *before* completing OAuth and hangs when
it gets a 401; `discovery_open` works around this by letting unauthenticated
requests to `/t/{tenant}/s/{service}/mcp` through **only** for single (non-batch)
JSON-RPC `initialize`, `ping`, and `tools/list` messages, plus the SSE GET
stream. `tools/call` and everything else still requires a valid token, and no
identity headers are ever injected on unauthenticated requests.

For production, set `tls.mode: acme` (or `manual`) in `tunneld.yaml`, point
`public_base_url` at your host, and use `wss://` in `agent.yaml`.

## Admin CLI (M1)

`mcptunnel` talks to the `/api/v1` control plane over HTTP; it stores its
session (server + bearer token) in `~/.mcptunnel/session`:

```sh
# one-time bootstrap with the setup token tunneld prints on first run
go run ./cmd/mcptunnel-admin bootstrap --server http://localhost:8484 --setup-token <printed-by-tunneld>

go run ./cmd/mcptunnel-admin invite create           # mint a one-time signup code
go run ./cmd/mcptunnel-admin tenant list
go run ./cmd/mcptunnel-admin tenant disable acme   # public endpoints for acme start returning 404
go run ./cmd/mcptunnel-admin tenant enable acme
go run ./cmd/mcptunnel service create acme/demo  # prints the agent key
go run ./cmd/mcptunnel audit tail acme -n 50
go run ./cmd/mcptunnel keys rotate acme
```

Every tenant/service/token operation is recorded in the per-tenant
`audit_log` table.

## Docker

```sh
docker build --target tunneld -t openai-tunnel-oauth/tunneld .
docker build --target tunnel-agent -t openai-tunnel-oauth/agent .
# or: docker compose up -d   (SQLite-backed, config in ./data)
```

### Multi-arch / ARM images

Both images are distroless static binaries and build for any platform:

```sh
docker buildx build --platform linux/amd64,linux/arm64 \
  --target tunneld -t openai-tunnel-oauth/tunneld .
docker buildx build --platform linux/amd64,linux/arm64 \
  --target tunnel-agent -t openai-tunnel-oauth/agent .
```

### Bare-metal: Ubuntu 24.04 + user supervisord (no Docker)

```sh
git clone <this repo> && cd openai-tunnel-oauth
bash scripts/setup-ubuntu-24.04.sh
```

The script installs a user-local Go toolchain, builds both binaries into
`~/tunneld/bin`, grants `cap_net_bind_service` so tunneld binds :443 as a
normal user, opens 443 in ufw, and installs supervisord as a **user-level**
systemd unit (`systemctl --user`, with lingering enabled so it starts at
boot). No root daemon, no Docker. Then:

```sh
$EDITOR ~/tunneld/tunneld.yaml                 # public_base_url, acme.email
systemctl --user start supervisord
supervisorctl -c ~/tunneld/supervisord.conf status
cat ~/tunneld/data/setup_token                   # one-time bootstrap token (deleted after use)
```

All state is `~/tunneld/data/tunneld.db` — back it up with
`sqlite3 ~/tunneld/data/tunneld.db ".backup 'backup.db'"`.

## Production checklist

- `public_base_url` = `https://your-host`, `tls.mode: acme`, ACME email set;
  only port 443 inbound (TLS-ALPN-01 needs no :80).
- `oauth.allowed_redirect_hosts: ["chatgpt.com"]` to restrict DCR/authorize.
- Configure per-tenant IdP providers via `mcptunnel idp set` (not `dev_auth`) with allowlists.
- Set an `identity_secret` per service (`mcptunnel service create --identity-secret`).
- In ChatGPT: Settings → Connectors → Advanced → Developer Mode, then
  Create with MCP URL `https://your-host/t/<tenant>/s/<service>/mcp`, auth: OAuth.

## Tests

```sh
go test ./...
```
