#!/bin/sh
# Render caddy/lore configs from *.tmpl using values in .env.
# Idempotent: safe to re-run after editing .env or the templates.
set -eu
cd "$(dirname "$0")"

[ -f .env ] || { echo "error: copy .env.example to .env and edit it first" >&2; exit 1; }

# Read .env literally, line by line. Do NOT source it. Strip one layer of
# surrounding single quotes so $-containing values stay docker-compose-safe.
while IFS= read -r line || [ -n "$line" ]; do
    case "$line" in ''|'#'*) continue ;; esac
    key=${line%%=*}
    val=${line#*=}
    case $val in
        \'*\') val=${val#\'}; val=${val%\'} ;;
    esac
    export "$key=$val"
done < .env

for v in LORE_HOST DEX_HOST LORE_AUTH_HOST LORE_WEB_HOST; do
    eval "val=\${$v:-}"
    [ -n "$val" ] || { echo "error: $v is not set in .env" >&2; exit 1; }
done

render() {
    python3 - "$1" "$2" <<'PYEOF'
import os, sys
tmpl, out = sys.argv[1], sys.argv[2]
text = open(tmpl).read()
keys = ["LORE_HOST", "DEX_HOST", "LORE_AUTH_HOST", "LORE_WEB_HOST"]
for k in keys:
    text = text.replace("{{%s}}" % k, os.environ.get(k, ""))
if "{{" in text:
    sys.exit(f"error: unrendered placeholder remains in {out}")
open(out, "w").write(text)
print(f"rendered {out}")
PYEOF
}

export LORE_HOST DEX_HOST LORE_AUTH_HOST LORE_WEB_HOST

render caddy/Caddyfile.tmpl  caddy/Caddyfile
render lore/local.toml.tmpl  lore/local.toml

echo "done. next: build the loreserver image (see README), then: docker compose up -d"
