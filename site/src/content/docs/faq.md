---
title: FAQ
description: Frequently asked questions about mcptunnels.
---

**Is there a hosted instance I can use?**
Yes — `https://tunnel.mcptunnels.xyz` is the default `--server`, so `mcptunnel expose -- <cmd>`
works out of the box. Run your own `tunneld` (and pass `--server`) whenever you'd rather not
trust a third-party relay.

**What happens after 24 hours?**
The tenant is deleted and the URL returns 404. Re-run `expose` for a fresh URL. Ctrl-C does the
same thing immediately.

**Can I get a stable/permanent URL?**
No — ephemeral URLs are the design. It keeps the service account-free and limits the blast
radius of a leaked URL. Permanent tunnels are on the [roadmap](/mcptunnels/roadmap/).

**Is my traffic encrypted?**
Client ↔ tunneld is TLS when tunneld runs with ACME or manual certs. But the tunnel is not
end-to-end encrypted: the tunneld operator can read every payload. Don't tunnel secrets through
a relay you don't control.

**Can I tunnel a non-MCP HTTP service?**
No. The CLI expects an MCP server command (stdio); the bridge speaks MCP.

**Does it work behind NAT / on a laptop that sleeps?**
NAT yes — the agent dials outbound. Sleeping closes the connection; the agent reconnects on
wake, and the same URL keeps working while the tenant lives.

**Why not ngrok / cloudflared?**
Generic tunnels forward raw TCP/HTTP. mcptunnels takes an MCP server command, bridges stdio to
Streamable HTTP, requires no account, and is ephemeral by default. If you already have an MCP
server listening on a port with its own HTTP transport, a generic tunnel works fine —
mcptunnels removes the stdio bridging step and everything around it.
