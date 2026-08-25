---
title: Security
description: Trust model, threat model, and how to report vulnerabilities.
---

## Trust model

mcptunnels provides anonymous, ephemeral quick tunnels. Understand the following before using
it:

- **OAuth 2.1 by default, but no identity.** Public endpoints require an authorization-code
  flow whose authorize page asks for the random password `expose` generated — so the URL alone
  is not enough. There is no user login or account: one password per tunnel, known only to
  whoever ran `expose` and whoever they share it with.
- **`--no-auth` URLs are the only secret.** With `--no-auth`, anyone who learns the URL can
  call the exposed server until the tunnel is stopped or expires. Treat URLs like passwords.
- **The tunneld operator can inspect traffic.** The tunnel is not end-to-end encrypted — all
  payloads transit the tunneld server. Do not tunnel private or sensitive data through a
  tunneld you do not control.
- **Ephemeral by design.** Quick tunnel tenants expire after 24 hours; URLs stop working after
  that.
- **Rate limiting is best-effort.** The per-IP rate limit on tunnel creation is not a strong
  anti-abuse guarantee.

In short: use mcptunnels for development and testing, not for private production traffic.

## Threat model details

- The **agent key** (`tun_agent_<48 hex>`) is the write side: only its bcrypt hash is stored,
  it is shown once by `expose`, and it dies with the tenant.
- The authorize-page password is stored as a bcrypt hash; one password per tunnel.
- TLS (ACME by default) protects both the agent WebSocket and public traffic in transit.
- One-time authorization codes, per-tenant ES256 JWT signing keys, and DCR client
  registrations all cascade-delete with the tenant.

The full threat model lives in
[DESIGN.md](https://github.com/terragohan/mcptunnels/blob/main/DESIGN.md).

## Reporting a vulnerability

Please do not open public issues for security vulnerabilities. Instead:

- Open a
  [private security advisory](https://github.com/terragohan/mcptunnels/security/advisories/new)
  on GitHub, or
- Contact the maintainer (@terragohan) through GitHub.

Only the latest commit on `main` and the most recent release receive security fixes.

## Abuse

Quick tunnels are anonymous and unauthenticated, so tunneld can be abused to proxy content the
operator did not choose. To report abuse on the hosted instance (`tunnel.mcptunnels.xyz`),
open a GitHub issue with the tunnel URL. The operator can kill any tenant instantly with
`tunneld -config tunneld.yaml -kill-tenant <slug>`. The hosted instance is best-effort: no
SLA, no uptime or takedown-time guarantee.
