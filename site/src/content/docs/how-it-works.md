---
title: How it works
description: Outbound WebSocket + yamux tunnel, stdio-to-HTTP bridging, and per-tunnel OAuth — no inbound ports, no accounts.
---

```
your machine                                  public host
┌──────────────────────┐    outbound WSS    ┌──────────────┐
│ mcp server (stdio)   │◀──────────────────│   tunneld    │◀── MCP client
│   ▲                  │   yamux streams    │  /t/q-*/mcp  │    (HTTPS)
│   └ bridge (loopback)│                    └──────────────┘
│   └ mcptunnel expose │  POST /api/v1/quick creates the tunnel
└──────────────────────┘
```

1. `expose` asks tunneld for a quick tunnel (`POST /api/v1/quick`, sending a generated
   password) and gets an ephemeral tenant (`q-*`, 24h TTL) plus a one-time agent key.
2. It spawns your command and bridges stdio to loopback HTTP.
3. The agent dials **outbound** to tunneld (WebSocket + yamux) — no inbound ports, works
   behind NAT.
4. tunneld reverse-proxies public requests over that connection.

There is no separate agent binary and no account system of any kind.

## On the wire

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
└── GET  /healthz
```

## Lifecycle

- A janitor deletes expired tenants every minute; their URLs start returning 404 and their
  agent keys stop validating.
- Ctrl-C on `expose` deletes the tunnel server-side immediately.
- Sleeping your laptop closes the connection; the agent reconnects on wake and the same URL
  keeps working while the tenant lives.

Full details and the complete threat model:
[DESIGN.md](https://github.com/terragohan/mcptunnels/blob/main/DESIGN.md).
