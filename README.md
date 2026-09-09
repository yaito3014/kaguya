# kaguya

Self-hosted [Lore](https://github.com/EpicGames/lore) version-control server,
authenticated by the shared Dex IdP on the **iroha** VPS.

Lore speaks QUIC (UDP 41337) for clone/push, so it is published directly rather
than through Caddy. Caddy issues the QUIC TLS certificate for `LORE_HOST`, and
Lore reads it from the shared `caddy-data` volume. Token verification uses
iroha's Dex: issuer `https://<DEX_HOST>/dex`, audience `<LORE_HOST>`.

## Requirements

- A VPS with a public IP; ports 80/443 (ACME) and 41337 (TCP+UDP) open; Docker + Compose
- An A record for `lore.` pointing at this VPS, DNS-only (grey cloud)
- The `iroha` stack already running, with Dex reachable at `https://<DEX_HOST>/dex`
- `openssl` and `python3` for `setup.sh`

## Build the loreserver image

No public image exists yet (the upstream publish workflow is a stub), so build
it from source. The Rust build needs several GB of RAM; build on a bigger
machine and transfer if this VPS is small:

    git clone https://github.com/EpicGames/lore
    cd lore
    docker build --platform linux/amd64 -f lore-server/Dockerfile -t loreserver:v0.9.0 .
    # if built elsewhere, load it onto this VPS:
    #   docker save loreserver:v0.9.0 | ssh kaguya 'docker load'

## Quick start

    cp .env.example .env
    $EDITOR .env          # LORE_HOST, DEX_HOST
    ./setup.sh            # renders caddy + lore configs
    docker compose up -d

Interactive login and refresh need UCS and do not work through Dex, so use the
device-flow helper `examples/get-token.sh` to get a token, then hand it to the CLI:

    TOKEN=$(./examples/get-token.sh)
    lore auth login --token-type lore --token "$TOKEN" --auth-url https://dex.yai.to/dex lore://lore.yai.to:41337

## Notes

- **`[environment]` is undocumented upstream.** Re-check `lore/local.toml.tmpl`
  against the Lore source on upgrade (verified against v0.9.0).
- The QUIC cert path in `lore/local.toml.tmpl` follows Caddy's ACME (Let's
  Encrypt) layout; if you change ACME CA, update the directory name.
- `permission_claim` is commented out: Dex `staticPasswords` emit no `groups`
  claim. Enable it once a real connector (GitHub, LDAP, ...) is configured.
