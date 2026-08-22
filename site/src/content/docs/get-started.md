---
title: Get started
description: Install mcptunnel and expose a local MCP server at a public URL in under a minute.
---

## Install

Prebuilt binaries for Linux and macOS (amd64/arm64) are attached to each
[GitHub release](https://github.com/terragohan/mcptunnels/releases), along with a
`checksums_<os>_<arch>.txt` per platform — verify with
`shasum -a 256 -c checksums_<os>_<arch>.txt` before unpacking.

With Go 1.26+:

```sh
go install github.com/terragohan/mcptunnels/cmd/mcptunnel@latest
```

## Expose an MCP server

One command. `expose` spawns your server, bridges stdio to HTTP, and dials **outbound** to the
hosted relay — no inbound ports, works behind NAT:

```sh
mcptunnel expose -- npx -y @modelcontextprotocol/server-everything
```

It prints the public endpoint and password, and holds the tunnel open:

```
https://tunnel.mcptunnels.xyz/t/q-3k9x2mab7c/s/mcp

  password: 9f2c1ab4e7d03815a6c02b94
```

By default `expose` tunnels through the hosted instance at `https://tunnel.mcptunnels.xyz`.
Pass `--server` only to use a different relay (for example your own
[self-hosted tunneld](/mcptunnels/self-hosting/)).

## Connect a client

- **Claude Code**: `claude mcp add --transport http demo <printed-url>`
- **ChatGPT / Cursor / others**: add the URL as a remote (streamable HTTP) MCP server. OAuth is
  on by default — clients discover it automatically and the authorize page asks for the printed
  password. Use `--no-auth` for a plain unauthenticated endpoint.

Then call a tool. That's the whole loop.

## Tearing down

Ctrl-C stops everything: `expose` deletes the tunnel server-side (the URL and password die
immediately) and exits if the MCP server exits. After 24 hours the tunnel is deleted
automatically if it is still around.

## Quickstart against a local tunneld

Terminal A — start tunneld (plain HTTP on :8484):

```sh
curl -sSL https://raw.githubusercontent.com/terragohan/mcptunnels/main/tunneld.yaml -o /tmp/tunneld.yaml
go run github.com/terragohan/mcptunnels/cmd/tunneld@latest -config /tmp/tunneld.yaml
```

Terminal B — expose any stdio MCP server through it:

```sh
mcptunnel expose --server http://localhost:8484 -- \
  npx -y @modelcontextprotocol/server-everything
```

:::caution
`--no-auth` tunnel URLs are **unauthenticated**: anyone who has the URL can call your server's
tools, and all traffic transits the relay operator. Expose throwaway servers only — never
private data. See [Security](/mcptunnels/security/).
:::
