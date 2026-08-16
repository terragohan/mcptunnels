# Roadmap

Where mcptunnels is headed. Roughly ordered; no dates — this is a spare-time
project and priorities follow real user pain.

## v0.1 — MVP (today)

- Anonymous quick tunnels: `mcptunnel expose -- <cmd>` → public URL.
- No accounts, no OAuth; the unguessable URL is the only secret.
- 24h TTL; a janitor sweeps expired tenants.
- Self-hosted `tunneld`: single binary + SQLite, ACME TLS, Docker or
  bare-metal.
- End-to-end tested data plane (agent WebSocket + yamux → proxy → stdio
  bridge), SSE streaming, automatic agent reconnect.

## Next: permanent tunnels

The MVP's ephemerality is the feature that lets us skip accounts — and the
first thing real users will outgrow.

- **Named, stable URLs.** Claim `/<you>/<name>` once, keep it across
  restarts, reboots, and laptop sleeps.
- **Bring-your-own identity, minimally.** The smallest possible account
  system — likely invite/token-based signup via the CLI, no web app.
- **Multiple services per identity**, each with its own stable URL and
  independent agent keys.
- **Lifecycle management** from the CLI: list, rotate keys, revoke, delete.

## Then: MCP servers as scalable HTTP services

Today `expose` bolts a public URL onto a single local process. The bigger
destination is making MCP servers easy to *run and scale* as Streamable HTTP
services — not just reachable, but deployable:

- **A stdio-to-HTTP framework, standalone.** The bridge inside `expose`
  becomes a library/thin runtime you can embed: take any stdio MCP server
  and serve it as a proper Streamable HTTP endpoint you can put behind a
  load balancer.
- **Deployment targets.** Opinionated recipes — and eventually adapters —
  for running MCP servers where HTTP services already scale: containers,
  VMs, and edge platforms like Cloudflare Workers, with the tunnel as the
  dev-time on-ramp and these as the production targets.
- **Session and lifecycle handling done right once.** Streamable HTTP
  sessions, stateless vs. stateful server modes, horizontal scaling
  semantics — handled in the framework instead of re-derived (badly) by
  every server author.
- **Graduation path.** Develop against a quick tunnel on your laptop; deploy
  the same server to real infrastructure with the same transport. The
  tunnel becomes the on-ramp, not the destination.

## Later: OAuth assistance

The hard part of putting an MCP server on the internet isn't connectivity —
it's that hosted clients (ChatGPT, Claude) increasingly require OAuth, and
most local MCP servers don't speak it. mcptunnels should bridge that gap:

- **Optional per-tunnel OAuth**: tunneld acts as the authorization server in
  front of your MCP server — discovery metadata, DCR, PKCE, the works — so a
  stdio server with zero auth code becomes a compliant OAuth-protected
  endpoint.
- **Pluggable identity**: start with a simple per-tunnel password/login
  page; later, bring-your-own IdP (Google, GitHub, enterprise OIDC).
- **Audience isolation**: tokens scoped to a single tunnel, so one
  compromised credential can't roam.
- **Pass-through identity headers** to the local server, so it can make
  per-user decisions without implementing OAuth itself.

This was prototyped in an earlier iteration of the repo and removed to ship
the MVP faster; the design work survives in git history.

## Explicit non-goals (for now)

- Generic TCP/HTTP tunneling of non-MCP services (ngrok's job, done well).
- A hosted, billing-backed SaaS. (There is a default public relay at
  `https://tunnel.mcptunnels.xyz` for convenience — it's free and
  best-effort, and self-hosting stays a first-class path.)
- A web dashboard.

## How to influence this

File an issue describing your use case — especially if the MVP's 24h,
unauthenticated model is the thing blocking you. That's the signal that
permanent tunnels should move up.
