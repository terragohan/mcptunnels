# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-08-16

Initial public release.

### Added

- `mcptunnel expose -- <cmd>`: expose a local MCP server over a public URL in one command.
- Anonymous quick tunnels: no accounts, no sign-up, URL-as-secret.
- Ephemeral tenants (`q-*` IDs) with a 24-hour TTL.
- `tunneld` server with automatic HTTPS (ACME) and a SQLite-backed store.
- Self-hosting support: single binary, Docker image, and Ubuntu 24.04 setup script.
