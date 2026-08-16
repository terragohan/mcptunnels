# openai-tunnel-oauth

Self-hosted quick tunnels for MCP servers, ngrok-style. `tunneld` runs on a
public host; `mcptunnel expose -- <cmd>` runs a local stdio MCP server and
dials **outbound** to `tunneld` (WebSocket + yamux), which reverse-proxies
public HTTP requests over that tunnel. There are no accounts: every tunnel is
anonymous and ephemeral (24h TTL), and the unguessable URL is the only
secret. See [DESIGN.md](DESIGN.md) for the architecture and threat model.

## Quickstart

```sh
# 1. Terminal A — start tunneld (plain HTTP on :8484, tls.mode: disabled).
go run ./cmd/tunneld -config ./tunneld.yaml

# 2. Terminal B — expose any stdio MCP server at a temporary public URL.
go run ./cmd/mcptunnel expose --server http://localhost:8484 -- \
  npx -y @modelcontextprotocol/server-everything
```

`expose` asks tunneld for a quick tunnel (`POST /api/v1/quick` → random
`q-*` tenant, one open service, agent key), spawns the MCP server, bridges
stdio to HTTP on loopback, and connects the tunnel agent — all in one
process. It prints the public endpoint:

```
http://localhost:8484/t/q-3k9x2mab7c/s/mcp/mcp
```

No signup, no session file. Anyone who has the URL can use the server; the
tunnel expires after 24 hours (a tunneld janitor deletes the tenant). Ctrl-C
stops everything; `expose` exits if the MCP server process exits.

## tunneld

Endpoints:

- `POST /api/v1/quick` — unauthenticated; creates an ephemeral tenant +
  service and returns the agent key. Rate-limited to 10/hour per remote IP.
- `GET /tunnel/connect` — agent WebSocket; authenticated with the agent key
  (`Authorization: Bearer`, plus `X-Tenant` / `X-Service-Name` headers).
- `/t/{tenant}/s/{service}/...` — the public MCP proxy; unauthenticated
  ("open"), the URL is the secret.
- `GET /healthz` — liveness.

Config (`tunneld.yaml`): `listen`, `public_base_url`, `tls` (acme / manual /
disabled), `database_path` (SQLite). That's all.

## Docker

```sh
docker build --target tunneld -t openai-tunnel-oauth/tunneld .
# or: docker compose up -d   (SQLite-backed, config in ./data)
```

Multi-arch: the image is a distroless static binary and builds for any
platform:

```sh
docker buildx build --platform linux/amd64,linux/arm64 \
  --target tunneld -t openai-tunnel-oauth/tunneld .
```

### Bare-metal: Ubuntu 24.04 + user supervisord (no Docker)

```sh
git clone <this repo> && cd openai-tunnel-oauth
bash scripts/setup-ubuntu-24.04.sh
```

The script installs a user-local Go toolchain, builds `tunneld` and
`mcptunnel` into `~/tunneld/bin`, grants `cap_net_bind_service` so tunneld
binds :443 as a normal user, opens 443 in ufw, and installs supervisord as a
**user-level** systemd unit (`systemctl --user`, with lingering enabled so it
starts at boot). No root daemon, no Docker. Then:

```sh
$EDITOR ~/tunneld/tunneld.yaml                 # public_base_url, acme.email
systemctl --user start supervisord
supervisorctl -c ~/tunneld/supervisord.conf status
```

All state is `~/tunneld/data/tunneld.db` — back it up with
`sqlite3 ~/tunneld/data/tunneld.db ".backup 'backup.db'"` (throwaway state:
quick tunnels only).

## Production checklist

- `public_base_url` = `https://your-host`, `tls.mode: acme`, ACME email set;
  only port 443 inbound (TLS-ALPN-01 needs no :80).
- Remember: every tunnel URL is unauthenticated. Tunnels are for sharing
  throwaway MCP servers, not private data.

## Tests

```sh
go test ./...
```
