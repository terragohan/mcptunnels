# AGENTS.md

Guidance for AI coding agents (OpenAI Codex and others) working in or with
this repository.

## What this is

mcptunnels: anonymous, ephemeral (24h) quick tunnels for MCP servers,
ngrok-style. `tunneld` runs on a public host; `mcptunnel expose` runs a local
stdio MCP server and dials **outbound** to tunneld (WebSocket + yamux), which
reverse-proxies public HTTP requests over the tunnel. No accounts — the
public endpoint is OAuth 2.1-gated behind a CLI-generated password by default
(`--no-auth` for open URLs). See README.md and DESIGN.md.

## Using the CLI (mcptunnel)

The canonical usage guide is the skill file
[.skills/mcptunnel/SKILL.md](.skills/mcptunnel/SKILL.md). Read it before
helping a user expose an MCP server or troubleshoot a tunnel. Key points:

- One command: `mcptunnel expose -- <mcp server command>` (defaults to the
  hosted relay `https://tunnel.mcptunnels.xyz`; `--server` overrides).
- No signup/login; tunnels expire after 24h (Ctrl-C deletes the tunnel
  server-side); OAuth is on by default with a generated password the CLI
  prints — share URL + password together, and warn users: throwaway servers
  only, never private data.

## Working in this repo

- Build: `go build ./...` — test: `go test ./... -count=1` — lint:
  `go vet ./...` and `gofmt -l .` (must be empty). CI runs exactly these.
  `make build` builds both binaries into `./dist/` (git-ignored);
  `make test` / `make lint` / `make clean` wrap the same checks.
- Layout: `cmd/tunneld` (server), `cmd/mcptunnel` (CLI), `internal/{agent,
  bridge,cli,config,controlplane,gateway,oauth,proxy,store,tunnelproto}`.
- Conventions: standard library only where possible; SQLite via
  modernc.org/sqlite; config is strict (unknown yaml keys fail startup).
- Releases: tag `v*`; the release workflow cross-compiles both binaries.
