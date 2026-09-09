#!/bin/sh
# Device-flow token helper: obtains a Lore access token from Dex.
#
# Interactive login and refresh need UCS and do not work through Dex, so this
# device-flow helper is the supported way to authenticate the lore CLI.
#
# Usage:
#   TOKEN=$(./get-token.sh)
#   lore auth login --token-type lore --token "$TOKEN" \
#     --auth-url https://dex.yai.to/dex lore://lore.yai.to:41337
#
# Override the defaults with env vars if needed:
#   DEX_URL (default https://dex.yai.to/dex), LORE_CLIENT_ID (default lore.yai.to)
set -eu

DEX="${DEX_URL:-https://dex.yai.to/dex}"
CLIENT_ID="${LORE_CLIENT_ID:-lore.yai.to}"
SCOPE="openid profile email"

field() { python3 -c "import json,sys; print(json.load(sys.stdin).get('$1',''))"; }

# 1. Device authorization request (RFC 8628)
resp=$(curl -s -X POST "$DEX/device/code" -d "client_id=$CLIENT_ID" -d "scope=$SCOPE")
device_code=$(printf '%s' "$resp" | field device_code)
[ -n "$device_code" ] || { echo "device authorization failed: $resp" >&2; exit 1; }
uri=$(printf '%s' "$resp" | field verification_uri_complete)
[ -n "$uri" ] || uri=$(printf '%s' "$resp" | field verification_uri)
user_code=$(printf '%s' "$resp" | field user_code)
interval=$(printf '%s' "$resp" | field interval); interval=${interval:-5}

echo "Open this URL and log in (user code: $user_code):" >&2
echo "  $uri" >&2

# 2. Poll the token endpoint until the user approves
while :; do
  sleep "$interval"
  tok=$(curl -s -X POST "$DEX/token" \
    -d 'grant_type=urn:ietf:params:oauth:grant-type:device_code' \
    -d "device_code=$device_code" -d "client_id=$CLIENT_ID")
  access_token=$(printf '%s' "$tok" | field access_token)
  [ -n "$access_token" ] && { printf '%s\n' "$access_token"; exit 0; }
  err=$(printf '%s' "$tok" | field error)
  case "$err" in
    authorization_pending|slow_down|'') : ;;
    *) echo "token error: $err" >&2; exit 1 ;;
  esac
done
