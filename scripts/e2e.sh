#!/usr/bin/env bash
# Binary-level end-to-end test: builds tunneld + mcptunnel, runs both against a
# fake HTTP upstream and a fake stdio MCP server, and exercises the real
# process wiring (remote --url mode, stdio mode, header policy, Ctrl-C delete,
# and `run` bridging a remote endpoint to local stdio).
set -euo pipefail

cd "$(dirname "$0")/.."
REPO_ROOT=$(pwd)

# --- Ports must be free (a leftover process would corrupt the results). -------
for port in 8765 8799; do
  if lsof -nP -iTCP:"$port" -sTCP:LISTEN >/dev/null 2>&1; then
    echo "FAIL: port $port is already in use; kill the leftover process first" >&2
    exit 1
  fi
done

TMP=$(mktemp -d)
PIDS=()

cleanup() {
  for pid in "${PIDS[@]:-}"; do
    kill "$pid" >/dev/null 2>&1 || true
  done
  # Give children a moment to die, then escalate.
  for pid in "${PIDS[@]:-}"; do
    kill -9 "$pid" >/dev/null 2>&1 || true
  done
  rm -rf "$TMP"
}
trap cleanup EXIT

fail() {
  echo "FAIL: $*" >&2
  exit 1
}

step() { echo "==> $*"; }

# --- Build both binaries into the temp dir. ----------------------------------
step "building tunneld and mcptunnel"
go build -o "$TMP/tunneld" ./cmd/tunneld
go build -o "$TMP/mcptunnel" ./cmd/mcptunnel

# --- Fake HTTP upstream: echoes request metadata as JSON. ---------------------
cat > "$TMP/upstream.py" <<'PY'
import json
from http.server import BaseHTTPRequestHandler, HTTPServer

class Handler(BaseHTTPRequestHandler):
    def _echo(self):
        n = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(n) if n else b""
        try:
            body_in = json.loads(raw) if raw else None
        except ValueError:
            body_in = None
        body = json.dumps({
            "method": self.command,
            "path": self.path,
            "host": self.headers.get("Host"),
            "authorization": self.headers.get("Authorization"),
            "cookie": self.headers.get("Cookie"),
            "x_test_header": self.headers.get("X-Test-Header"),
            "body": body_in,
        }).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    do_GET = do_POST = do_DELETE = _echo

    def log_message(self, *args):
        pass

HTTPServer(("127.0.0.1", 8799), Handler).serve_forever()
PY

# --- Fake stdio MCP server: one JSON line per request. ------------------------
cat > "$TMP/fake-mcp.py" <<'PY'
import json, sys

for line in sys.stdin:
    line = line.strip()
    if not line:
        continue
    try:
        req = json.loads(line)
    except ValueError:
        continue
    if req.get("method") in ("initialize", "tools/list"):
        print(json.dumps({"jsonrpc": "2.0", "id": req.get("id"), "result": {"ok": True}}), flush=True)
PY

# --- tunneld config. -----------------------------------------------------------
cat > "$TMP/tunneld.yaml" <<EOF
listen: "127.0.0.1:8765"
public_base_url: "http://127.0.0.1:8765"
tls:
  mode: disabled
database_path: "$TMP/tunneld.db"
EOF

# --- Start upstream + tunneld, wait for health. -------------------------------
step "starting upstream and tunneld"
python3 "$TMP/upstream.py" >"$TMP/upstream.log" 2>&1 &
PIDS+=($!)
"$TMP/tunneld" --config "$TMP/tunneld.yaml" >"$TMP/tunneld.log" 2>&1 &
PIDS+=($!)

for _ in $(seq 1 50); do
  curl -sf http://127.0.0.1:8765/healthz >/dev/null 2>&1 && break
  sleep 0.2
done
curl -sf http://127.0.0.1:8765/healthz >/dev/null 2>&1 || fail "tunneld did not become healthy (see $TMP/tunneld.log)"

# Wait for the public URL to appear in an expose log, echo it.
wait_for_url() { # <log file>
  local url=""
  for _ in $(seq 1 75); do
    url=$(grep -oE 'http://127.0.0.1:8765/t/[^ ]*' "$1" 2>/dev/null | head -n1 || true)
    [ -n "$url" ] && { echo "$url"; return 0; }
    sleep 0.2
  done
  return 1
}

# --- TEST A: remote URL mode + header policy. ---------------------------------
step "TEST A: --url mode with --header, client credentials stripped"
"$TMP/mcptunnel" expose --server http://127.0.0.1:8765 --no-auth \
  --url http://127.0.0.1:8799/mcp --header "X-Test-Header: hello" \
  >"$TMP/expose-a.log" 2>&1 &
PIDS+=($!)

URL_A=$(wait_for_url "$TMP/expose-a.log") || fail "mcptunnel (TEST A) did not print a public URL (see $TMP/expose-a.log)"
echo "    public URL: $URL_A"

BODY_A=$(curl -s -X POST "$URL_A/mcp" \
  -H 'Authorization: Bearer evil-jwt' -H 'Cookie: session=xyz')
echo "    upstream saw: $BODY_A"

echo "$BODY_A" | python3 -c '
import json, sys
b = json.load(sys.stdin)
assert b["path"] == "/mcp", "path: %r" % b["path"]
assert b["authorization"] is None, "authorization leaked: %r" % b["authorization"]
assert b["cookie"] is None, "cookie leaked: %r" % b["cookie"]
assert b["x_test_header"] == "hello", "x_test_header: %r" % b["x_test_header"]
' || fail "TEST A upstream response mismatch"

# --- TEST B: stdio mode. -------------------------------------------------------
step "TEST B: stdio MCP server mode"
"$TMP/mcptunnel" expose --server http://127.0.0.1:8765 --no-auth -- \
  python3 "$TMP/fake-mcp.py" >"$TMP/expose-b.log" 2>&1 &
MCP_PID=$!
PIDS+=($!)

URL_B=$(wait_for_url "$TMP/expose-b.log") || fail "mcptunnel (TEST B) did not print a public URL (see $TMP/expose-b.log)"
echo "    public URL: $URL_B"

BODY_B=$(curl -s -X POST "$URL_B" -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/list"}')
echo "    response: $BODY_B"
echo "$BODY_B" | grep -q '"ok":[[:space:]]*true' || fail "TEST B response missing '\"ok\": true'"

# --- TEST C: Ctrl-C deletes the tunnel. ---------------------------------------
step "TEST C: Ctrl-C deletes the tunnel (expect 404)"
kill -INT "$MCP_PID"
for _ in $(seq 1 25); do
  kill -0 "$MCP_PID" 2>/dev/null || break
  sleep 0.2
done
kill -0 "$MCP_PID" 2>/dev/null && fail "mcptunnel (TEST B) did not exit on SIGINT"

CODE=$(curl -s -o /dev/null -w '%{http_code}' -X POST "$URL_B" \
  -H 'Content-Type: application/json' -d '{"jsonrpc":"2.0","id":2,"method":"tools/list"}')
echo "    HTTP code after Ctrl-C: $CODE"
[ "$CODE" = "404" ] || fail "expected HTTP 404 after Ctrl-C, got $CODE"

# --- TEST D: `mcptunnel run` — remote HTTP MCP endpoint over local stdio. -----
# Pipes one JSON-RPC line into `run` pointed at TEST A's tunnel; stdin EOF
# must still deliver the reply (Serve drains in-flight requests on shutdown).
step "TEST D: run bridges a remote HTTP MCP endpoint to stdio"
BODY_D=$(echo '{"jsonrpc":"2.0","id":1,"method":"tools/list"}' | "$TMP/mcptunnel" run --url "$URL_A/mcp" 2>"$TMP/run-d.log")
echo "    reply: $BODY_D"
echo "$BODY_D" | grep -q '"method":[[:space:]]*"tools/list"' \
  || fail "TEST D reply missing the forwarded tools/list (see $TMP/run-d.log)"

# --- TEST E: token registry — managed bearer picked up automatically. --------
# Register a bearer for the echo upstream, then expose it WITHOUT --header:
# the registry entry must be injected (and client creds still stripped).
# Isolate the registry from the developer's real config: on macOS
# os.UserConfigDir ignores XDG_CONFIG_HOME, so override HOME too.
step "TEST E: token registry injects a managed bearer token"
export HOME="$TMP/home" XDG_CONFIG_HOME="$TMP/home/.config"
mkdir -p "$HOME"

"$TMP/mcptunnel" token add --url http://127.0.0.1:8799/mcp --bearer registry-key \
  || fail "mcptunnel token add failed"

"$TMP/mcptunnel" expose --server http://127.0.0.1:8765 --no-auth \
  --url http://127.0.0.1:8799/mcp \
  >"$TMP/expose-e.log" 2>&1 &
PIDS+=($!)

URL_E=$(wait_for_url "$TMP/expose-e.log") || fail "mcptunnel (TEST E) did not print a public URL (see $TMP/expose-e.log)"
echo "    public URL: $URL_E"

BODY_E=$(curl -s -X POST "$URL_E/mcp" \
  -H 'Authorization: Bearer evil-jwt' -H 'Cookie: session=xyz')
echo "    upstream saw: $BODY_E"

echo "$BODY_E" | python3 -c '
import json, sys
b = json.load(sys.stdin)
assert b["authorization"] == "Bearer registry-key", "registry token not injected: %r" % b["authorization"]
assert b["cookie"] is None, "cookie leaked: %r" % b["cookie"]
' || fail "TEST E upstream response mismatch"

step "PASS: all end-to-end checks succeeded"
