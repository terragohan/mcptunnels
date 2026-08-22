---
title: Self-hosting
description: Run your own tunneld relay — a single static binary plus a SQLite file, with automatic HTTPS via ACME.
---

`tunneld` is a single static binary plus a SQLite file. Config (`tunneld.yaml`) is four keys:
`listen`, `public_base_url`, `tls` (`acme` / `manual` / `disabled`), `database_path`. Unknown
keys fail startup.

```sh
docker build --target tunneld -t mcptunnels/tunneld .   # or compose up -d
```

For a real deployment (automatic HTTPS via ACME on :443, supervisord on Ubuntu 24.04), see
[`scripts/setup-ubuntu-24.04.sh`](https://github.com/terragohan/mcptunnels/blob/main/scripts/setup-ubuntu-24.04.sh).

Any cheap VPS with a domain works. Once it's up, point the CLI at it:

```sh
mcptunnel expose --server https://your-host -- <mcp server command>
```

## Endpoints

- `POST /api/v1/quick` — create a tunnel (unauthenticated, 10/hour per IP, persisted in SQLite
  so a restart does not reset it; hard cap of 500 live tunnels, then 503).
- `DELETE /api/v1/quick/{tenant}` — destroy a tunnel early (agent-key auth; `expose` calls it
  on exit so the URL and password die with the process).
- `GET /tunnel/connect` — agent WebSocket, authenticated by the agent key.
- `/t/{tenant}/s/{service}/...` — the public proxy. OAuth-gated by default; the authorize page
  requires the password `expose` prints.
- `GET /healthz` — liveness.

## Abuse takedown

Kill a tenant instantly (over SSH, no HTTP endpoint) — its public URL starts returning 404 and
its agent key stops validating:

```sh
tunneld -config tunneld.yaml -kill-tenant q-3k9x2mab7c
```

## Abuse controls

Quick-tunnel creation is unauthenticated, so the only guard is a deliberate, weak one: a
per-remote-IP rate limit of 10 tunnels/hour. A distributed botnet walks right past it.
Mitigating factors: tunnels are ephemeral (24h max), carry no identity, hold no data beyond the
connected agent, and cost the operator only a SQLite row plus an open WebSocket each. Operators
who need more should put tunneld behind a CDN/WAF rate limiter.
