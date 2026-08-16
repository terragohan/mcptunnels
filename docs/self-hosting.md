# Self-hosting tunneld

`tunneld` is a single static Go binary with one config file and one SQLite
database. It terminates TLS itself (ACME or manual certs) — there is nothing
else to run.

## Configuration reference (`tunneld.yaml`)

The config loader is strict: unknown YAML keys fail startup. All fields:

```yaml
# Address the public listener binds to. Production (acme/manual TLS) should
# be :443.
listen: ":443"

# Externally visible base URL. Public tunnel URLs are built from it
# (<public_base_url>/t/<q-slug>/s/mcp/mcp), so it must match exactly how
# clients reach this server (scheme, host, port).
public_base_url: "https://tunnel.example.com"

tls:
  # acme     — automatic Let's Encrypt certificates
  # manual   — provide your own cert/key
  # disabled — plain HTTP, development only (MCP clients generally require
  #            real HTTPS)
  mode: acme
  acme:
    cache_dir: "./acme-cache"   # where issued certs/keys are stored
    email: "you@example.com"    # must be a real address
  manual:
    cert_file: "./cert.pem"
    key_file: "./key.pem"

# SQLite database file (ephemeral tenants, services, agent-key hashes).
# May also be supplied via the DATABASE_PATH environment variable.
database_path: "./data/tunneld.db"
```

## ACME / TLS notes

- ACME uses the **TLS-ALPN-01** challenge, which only needs **port 443**
  reachable from the internet. Nothing ever listens on port 80.
- The ACME allowlist is derived from `public_base_url`'s host, so that
  hostname must resolve to this server before startup.
- Set a real `acme.email`; a placeholder address is rejected by Let's
  Encrypt (`invalidContact`) and tunneld will fail to obtain a certificate.
- Issued certs live in `acme.cache_dir`; keep that directory persistent.

## Docker

```sh
docker build --target tunneld -t mcptunnels/tunneld .
# or: docker compose up -d   (SQLite-backed, config in ./data)
```

The compose file mounts `./data` at `/data` (config, SQLite DB, ACME cache)
and publishes only `443:443`. The image is a distroless static binary and
builds multi-arch:

```sh
docker buildx build --platform linux/amd64,linux/arm64 \
  --target tunneld -t mcptunnels/tunneld .
```

## Bare metal: Ubuntu 24.04 + user supervisord (no Docker)

```sh
git clone https://github.com/generalpiston/mcptunnels && cd mcptunnels
bash scripts/setup-ubuntu-24.04.sh
```

The script:

1. installs git, supervisor, sqlite3, ufw via apt,
2. installs a user-local Go toolchain under `~/tunneld/go`,
3. builds `tunneld` and `mcptunnel` into `~/tunneld/bin`,
4. grants `cap_net_bind_service` so tunneld binds :443 as a normal user,
5. opens 443 in ufw,
6. writes `~/tunneld/tunneld.yaml` (edit it before starting!),
7. writes `~/tunneld/supervisord.conf` and a **user-level** systemd unit
   (`systemctl --user`, with lingering enabled so it starts at boot).

No root daemon, no Docker. Then:

```sh
$EDITOR ~/tunneld/tunneld.yaml                 # public_base_url, acme.email
systemctl --user start supervisord
supervisorctl -c ~/tunneld/supervisord.conf status
```

## Production checklist

- `public_base_url` = `https://your-host`, `tls.mode: acme`, real ACME email;
  only port 443 inbound (TLS-ALPN-01 needs no :80).
- If your DNS is behind Cloudflare, set the record to **DNS only** (grey
  cloud) — proxied mode breaks TLS-ALPN-01 and returns 521s.
- Remember: every tunnel URL is unauthenticated. Tunnels are for sharing
  throwaway MCP servers, not private data.

## Backups

All state is one SQLite file (`database_path`). Back it up online with:

```sh
sqlite3 ~/tunneld/data/tunneld.db ".backup 'backup.db'"
```

The state is throwaway (quick tunnels only, 24h TTL), so losing it costs you
nothing but in-flight tunnels.
