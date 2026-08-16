# Security model

Condensed from [DESIGN.md](../DESIGN.md) §4–5. Read it before exposing
anything beyond a throwaway MCP server.

## URL-as-secret

Public MCP endpoints are **unauthenticated by design**. Anyone who learns
`https://host/t/<q-slug>/s/mcp/mcp` can call the exposed server until the
tunnel expires or the user stops `expose`. The only protection is
unguessability: ~56 bits of random slug plus the service path. Treat tunnel
URLs like passwords; do not post them anywhere public.

## Open tunnels

There is no authentication or authorization layer in front of exposed
services. If the MCP server you expose does not enforce its own auth, anyone
with the URL can use it. Only expose non-sensitive servers.

## Operator visibility

All tunnel payloads transit `tunneld`. The operator of the tunneld instance
can technically inspect every request and response flowing through it. Do
not tunnel private data through a tunneld you do not control.

## Weak rate limiting

Quick-tunnel creation (`POST /api/v1/quick`) is unauthenticated. The only
guard is a deliberately weak in-memory per-remote-IP rate limit (10
tunnels/hour, fixed windows, reset on restart). A distributed botnet walks
right past it. Operators who need more should put tunneld behind a CDN/WAF
rate limiter.

Mitigating factors: tunnels are ephemeral (24h TTL, enforced by a janitor
that deletes expired tenants every minute), carry no identity, hold no data
beyond the connected agent, and cost the operator only an SQLite row plus an
open WebSocket each.

## Agent keys

The agent key (`tun_agent_<48 hex>`) is the write side of a tunnel: only its
bcrypt hash is stored at rest, it is shown once by `expose`, and it dies
with the tenant when the tunnel expires.

## In transit

TLS (ACME by default) protects both the agent WebSocket and public traffic.
Run `tls.mode: disabled` only for local development.
