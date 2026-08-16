# Security Policy

## Reporting a Vulnerability

Please do not open public issues for security vulnerabilities. Instead:

- Open a [private security advisory](https://github.com/terragohan/mcptunnels/security/advisories/new) on GitHub, or
- Contact the maintainer (@terragohan) through GitHub.

We will acknowledge reports as soon as we can and coordinate a fix and disclosure timeline with you.

## Supported Versions

Only the latest commit on `main` and the most recent release receive security fixes. There is no long-term-support branch.

## Trust Model

mcptunnels provides anonymous, ephemeral quick tunnels. Please understand the following before using it:

- **URLs are the only secret.** Quick tunnel URLs contain an unguessable random token, but they are otherwise unauthenticated. Anyone with the URL can reach your exposed service. Treat URLs like passwords and do not share them.
- **Tunnels are open.** Services exposed via `mcptunnel expose` are publicly reachable without any authentication or authorization layer. If your MCP server does not enforce its own auth, anyone who discovers the URL can use it.
- **The tunneld operator can inspect traffic.** All tunnel payloads transit the tunneld server, and the operator can technically inspect them. Do not tunnel private or sensitive data through a tunneld you do not control.
- **Ephemeral by design.** Quick tunnel tenants expire after 24 hours; URLs stop working after that.
- **Rate limiting is best-effort.** The per-IP rate limit on the quick-tunnel creation endpoint is persisted in SQLite but still trivially bypassed by a distributed botnet; it is not a strong anti-abuse guarantee.

In short: use mcptunnels for development and testing, not for private production traffic. See [DESIGN.md](DESIGN.md) for the full threat model.

## Abuse

Quick tunnels are anonymous and unauthenticated, so tunneld can be abused to proxy content the operator did not choose. To report abuse on the hosted instance (`tunnel.mcptunnels.xyz`), open a GitHub issue with the tunnel URL. The operator can kill any tenant instantly with `tunneld -config tunneld.yaml -kill-tenant <slug>`. The hosted instance is best-effort: no SLA, no uptime or takedown-time guarantee.
