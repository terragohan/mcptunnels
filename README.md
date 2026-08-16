# mcptunnels

Self-hosted quick tunnels for MCP servers, ngrok-style. `tunneld` runs on a
public host; `mcptunnel expose -- <cmd>` runs a local stdio MCP server and
dials **outbound** to `tunneld` (WebSocket + yamux), which reverse-proxies
public HTTP requests over that tunnel. There are no accounts: every tunnel is
anonymous and ephemeral (24h TTL), and the unguessable URL is the only
secret. See [DESIGN.md](DESIGN.md) for the architecture and threat model.

## Install

Prebuilt binaries for Linux and macOS (amd64/arm64) are attached to each
[GitHub release](https://github.com/generalpiston/mcptunnels/releases).

With Go installed:

```sh
go install github.com/generalpiston/mcptunnels/cmd/mcptunnel@latest
```

With Docker (tunneld server only):

```sh
docker build --target tunneld -t mcptunnels/tunneld .
```

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

## Docs

- [docs/self-hosting.md](docs/self-hosting.md) — run tunneld in production
  (ACME, Docker, Ubuntu 24.04, backups).
- [docs/security.md](docs/security.md) — threat model and trust assumptions.
- [docs/troubleshooting.md](docs/troubleshooting.md) — common failure modes.
- [DESIGN.md](DESIGN.md) — architecture and design rationale.

## Tests

```sh
go test ./...
```

## License

[Apache 2.0](LICENSE). Security reports: see [SECURITY.md](SECURITY.md).
