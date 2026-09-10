#!/bin/sh
# Low-level device-flow reference: drives the OIDC device authorization grant
# (RFC 8628) with curl and prints the provider's raw access token.
#
# This is a reference only. The supported way to authenticate the lore CLI is
# `lore auth login` (kaguya-auth runs this same device flow for you, then mints
# the repository-scoped token loreserver actually trusts). loreserver rejects a
# raw provider token, so the token printed here is not usable on its own.
#
# Usage:
#   ./get-token.sh            # prints the access token (after you approve in a browser)
#
# Override the defaults with env vars if needed:
#   OIDC_ISSUER (default https://id.yai.to/application/o/lore/), LORE_CLIENT_ID (default lore.yai.to)
set -eu

ISSUER="${OIDC_ISSUER:-https://id.yai.to/application/o/lore/}"
CLIENT_ID="${LORE_CLIENT_ID:-lore.yai.to}"
SCOPE="openid profile email"

field() { python3 -c "import json,sys; print(json.load(sys.stdin).get('$1',''))"; }

# 0. Discover the endpoints. Trim a trailing slash so an issuer like ".../o/lore/"
#    does not yield a double-slashed (404) well-known URL.
disco=$(curl -s "${ISSUER%/}/.well-known/openid-configuration")
device_endpoint=$(printf '%s' "$disco" | field device_authorization_endpoint)
token_endpoint=$(printf '%s' "$disco" | field token_endpoint)
[ -n "$device_endpoint" ] && [ -n "$token_endpoint" ] || {
    echo "discovery failed for $ISSUER: $disco" >&2; exit 1; }

# 1. Device authorization request (RFC 8628)
resp=$(curl -s -X POST "$device_endpoint" -d "client_id=$CLIENT_ID" -d "scope=$SCOPE")
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
  tok=$(curl -s -X POST "$token_endpoint" \
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
