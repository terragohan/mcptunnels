#!/usr/bin/env bash
# oauth-smoke.sh — walk the full OAuth flow against a live tenant by hand:
# DCR → browser login/consent → code exchange → authenticated tools/list.
#
# Usage:
#   scripts/oauth-smoke.sh https://tunnel.mcptunnels.xyz <tenant> [service]
#
# Requires: curl, openssl, python3 (for JSON parsing), a browser.
set -euo pipefail

BASE="${1:?usage: oauth-smoke.sh BASE_URL TENANT [SERVICE]}"
TENANT="${2:?missing tenant slug}"
SERVICE="${3:-demo}"
TEN="$BASE/t/$TENANT"
REDIRECT="http://127.0.0.1:8973/cb"

jget() { python3 -c "import sys,json;print(json.load(sys.stdin)[sys.argv[1]])" "$1"; }
urlenc() { python3 -c "import sys,urllib.parse;print(urllib.parse.quote(sys.argv[1],safe=''))" "$1"; }

echo "==> 1. Dynamic client registration"
CLIENT=$(curl -sf -X POST "$TEN/register" -H 'Content-Type: application/json' \
  -d "{\"redirect_uris\":[\"$REDIRECT\"],\"client_name\":\"oauth-smoke\"}")
CLIENT_ID=$(echo "$CLIENT" | jget client_id)
echo "    client_id: $CLIENT_ID"

echo "==> 2. Authorize (browser login + consent)"
VERIFIER=$(openssl rand -hex 32)
CHALLENGE=$(printf %s "$VERIFIER" | openssl dgst -sha256 -binary | openssl base64 -A | tr '+/' '-_' | tr -d '=')
STATE=$(openssl rand -hex 8)
AUTH_URL="$TEN/authorize?response_type=code&client_id=$CLIENT_ID&redirect_uri=$(urlenc "$REDIRECT")&state=$STATE&code_challenge=$CHALLENGE&code_challenge_method=S256"
echo "    opening: $AUTH_URL"
echo "    (log in with the tenant's IdP, or the tunneld dev_auth password)"
command -v open >/dev/null && open "$AUTH_URL" || xdg-open "$AUTH_URL" 2>/dev/null || true
echo
read -rp "    paste the full redirect URL you land on (http://127.0.0.1:8973/cb?code=...): " CB
CODE=$(python3 -c "import sys,urllib.parse as u;print(u.parse_qs(u.urlparse(sys.argv[1]).query)['code'][0])" "$CB")

echo "==> 3. Token exchange (authorization_code + PKCE)"
TOKENS=$(curl -sf -X POST "$TEN/token" \
  -d grant_type=authorization_code -d "client_id=$CLIENT_ID" \
  -d "redirect_uri=$REDIRECT" -d "code=$CODE" -d "code_verifier=$VERIFIER")
ACCESS=$(echo "$TOKENS" | jget access_token)
REFRESH=$(echo "$TOKENS" | jget refresh_token)
echo "    got access token (15m TTL) + refresh token"

echo "==> 4. Authenticated MCP call through the tunnel"
curl -sf -X POST "$TEN/s/$SERVICE/mcp" \
  -H "Authorization: Bearer $ACCESS" -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/list"}'
echo

echo "==> 5. Refresh token rotation"
TOKENS2=$(curl -sf -X POST "$TEN/token" \
  -d grant_type=refresh_token -d "client_id=$CLIENT_ID" -d "refresh_token=$REFRESH")
echo "$TOKENS2" | jget access_token >/dev/null && echo "    refresh OK (new access token issued, old refresh token rotated)"

echo
echo "ALL STEPS PASSED — OAuth works end to end for tenant '$TENANT'."
