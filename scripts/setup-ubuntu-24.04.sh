#!/usr/bin/env bash
# setup-ubuntu-24.04.sh — install tunneld on Ubuntu 24.04 as a user-level
# supervisord service (no Docker, no root daemon).
#
# Run from a checkout of this repository:
#
#   bash scripts/setup-ubuntu-24.04.sh
#
# What it does (sudo is used only where marked):
#   1. apt: installs git, supervisor, sqlite3, ufw            [sudo]
#   2. installs a user-local Go 1.26 toolchain under ~/tunneld/go
#   3. builds tunneld + mcptunnel into ~/tunneld/bin
#   4. setcap cap_net_bind_service so tunneld can bind :443 as a user  [sudo]
#   5. ufw: allow 443/tcp                                     [sudo]
#   6. writes ~/tunneld/tunneld.yaml (edit it before starting!)
#   7. writes ~/tunneld/supervisord.conf and a systemd --user unit,
#      enables lingering so supervisord starts at boot         [sudo]
#
# After running: edit ~/tunneld/tunneld.yaml (public_base_url, acme email),
# then:
#   systemctl --user start supervisord
#   supervisorctl -c ~/tunneld/supervisord.conf status

set -euo pipefail

GO_VERSION=1.26.1
HOME_DIR="$HOME/tunneld"
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

case "$(uname -m)" in
  x86_64)  GOARCH=amd64 ;;
  aarch64) GOARCH=arm64 ;;
  *) echo "unsupported arch: $(uname -m)" >&2; exit 1 ;;
esac

echo "==> apt packages"
sudo apt-get update -qq
sudo apt-get install -y -qq git supervisor sqlite3 ufw curl ca-certificates

# The Go compiler needs ~2GB to build (modernc.org/sqlite is heavy); small
# droplets without swap get OOM-killed mid-build. Add a 2G swapfile if needed.
if [ "$(awk '/MemTotal/{print int($2/1024)}' /proc/meminfo)" -lt 2048 ] && ! swapon --show | grep -q .; then
  echo "==> low RAM and no swap: creating a 2G swapfile"
  sudo fallocate -l 2G /swapfile
  sudo chmod 600 /swapfile
  sudo mkswap /swapfile
  sudo swapon /swapfile
  grep -q '^/swapfile' /etc/fstab || echo '/swapfile none swap sw 0 0' | sudo tee -a /etc/fstab
fi

mkdir -p "$HOME_DIR"/{bin,data,log,run}

echo "==> Go $GO_VERSION ($GOARCH)"
if [ ! -x "$HOME_DIR/go/bin/go" ]; then
  curl -fsSL "https://go.dev/dl/go${GO_VERSION}.linux-${GOARCH}.tar.gz" -o /tmp/go.tgz
  rm -rf "$HOME_DIR/go"
  tar -C "$HOME_DIR" -xzf /tmp/go.tgz
  rm /tmp/go.tgz
fi
export PATH="$HOME_DIR/go/bin:$PATH"

echo "==> building"
(cd "$REPO_ROOT" && CGO_ENABLED=0 go build -buildvcs=false -trimpath -ldflags="-s -w" -o "$HOME_DIR/bin/tunneld" ./cmd/tunneld)
(cd "$REPO_ROOT" && CGO_ENABLED=0 go build -buildvcs=false -trimpath -ldflags="-s -w" -o "$HOME_DIR/bin/mcptunnel" ./cmd/mcptunnel)
sudo setcap cap_net_bind_service=+ep "$HOME_DIR/bin/tunneld"   # bind :443 as a user

echo "==> firewall"
sudo ufw allow 443/tcp
sudo ufw allow OpenSSH

if [ ! -f "$HOME_DIR/tunneld.yaml" ]; then
  cat > "$HOME_DIR/tunneld.yaml" <<EOF
listen: ":443"
public_base_url: "https://EDIT-ME.example.com"   # must match how clients reach this server
tls:
  mode: acme
  acme:
    cache_dir: "$HOME_DIR/data/acme-cache"
    email: "you@example.com"
database_path: "$HOME_DIR/data/tunneld.db"
EOF
  echo "    wrote $HOME_DIR/tunneld.yaml — EDIT public_base_url and acme.email before starting"
fi

cat > "$HOME_DIR/supervisord.conf" <<EOF
; User-level supervisord — no root daemon. Socket/pid live under ~/tunneld/run.
[unix_http_server]
file=$HOME_DIR/run/supervisor.sock

[supervisord]
logfile=$HOME_DIR/log/supervisord.log
pidfile=$HOME_DIR/run/supervisord.pid
nodaemon=false

[rpcinterface:supervisor]
supervisor.rpcinterface_factory = supervisor.rpcinterface:make_main_rpcinterface

[supervisorctl]
serverurl=unix://$HOME_DIR/run/supervisor.sock

[program:tunneld]
command=$HOME_DIR/bin/tunneld -config $HOME_DIR/tunneld.yaml
directory=$HOME_DIR
autostart=true
autorestart=true
startsecs=3
stdout_logfile=$HOME_DIR/log/tunneld.log
redirect_stderr=true
EOF

echo "==> systemd user unit (autostart at boot)"
mkdir -p "$HOME/.config/systemd/user"
cat > "$HOME/.config/systemd/user/supervisord.service" <<EOF
[Unit]
Description=supervisord (user)

[Service]
ExecStart=/usr/bin/supervisord -c $HOME_DIR/supervisord.conf -n
Restart=on-failure

[Install]
WantedBy=default.target
EOF
systemctl --user daemon-reload
systemctl --user enable supervisord
sudo loginctl enable-linger "$USER"   # keep user services running without a login session

cat <<EOF

Done. Next steps:

  1. Edit $HOME_DIR/tunneld.yaml (public_base_url, acme.email)
  2. Point your domain's A/AAAA record at this host (Cloudflare: DNS only, not proxied)
  3. systemctl --user start supervisord
  4. supervisorctl -c ~/tunneld/supervisord.conf status
  5. Try it out (anonymous quick tunnel, expires in 24h):
       mcptunnel expose --server https://<domain> -- <mcp server command>

Backups: the only state is $HOME_DIR/data/tunneld.db —
  sqlite3 $HOME_DIR/data/tunneld.db ".backup '\$HOME/tunneld/backups/tunneld.db'"
EOF
