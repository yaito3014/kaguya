# kaguya

Self-hosted [Lore](https://github.com/EpicGames/lore) version-control server,
authenticated by the shared Dex IdP on the **iroha** VPS.

Lore speaks QUIC (UDP 41337) for clone/push, so it is published directly rather
than through Caddy. Caddy issues the QUIC TLS certificate for `LORE_HOST`, and
Lore reads it from the shared `caddy-data` volume.

Authentication is a two-hop exchange. The client logs in to iroha's Dex (device
flow) for identity. The `kaguya-auth` service then verifies that Dex token and
mints a short-lived, repository-scoped token signed with its own key; loreserver
verifies *that* token (issuer `https://<LORE_AUTH_HOST>`, audience `<LORE_HOST>`,
JWKS read from the shared `auth-keys` volume). The scope loreserver's storage
and revision services require lives in the minted token's `resources` claim — a
raw Dex token carries none, which is why `kaguya-auth` re-issues it.

## Requirements

- A VPS with a public IP; ports 80/443 (ACME) and 41337 (TCP+UDP) open; Docker + Compose
- An A record for `lore.` pointing at this VPS, DNS-only (grey cloud)
- The `iroha` stack already running, with Dex reachable at `https://<DEX_HOST>/dex`
- A CNAME for `LORE_AUTH_HOST` pointing at this VPS (Caddy fronts `kaguya-auth`)
- `python3` for `setup.sh`

## Build the images

Neither image is published, so build both. The loreserver build needs several GB
of RAM; build on a bigger machine and transfer if this VPS is small. `kaguya-auth`
builds from `./auth` in this repo.

    # loreserver, from upstream source
    git clone https://github.com/EpicGames/lore
    cd lore
    docker build --platform linux/amd64 -f lore-server/Dockerfile -t loreserver:v0.9.0 .
    cd -

    # kaguya-auth, from this repo
    docker build --platform linux/amd64 -t kaguya-auth:0.2.0 ./auth

    # if built elsewhere, load them onto this VPS:
    #   docker save loreserver:v0.9.0 kaguya-auth:0.2.0 | ssh kaguya 'docker load'

`kaguya-auth` generates its RSA signing key on first start and persists it in the
`auth-keys` volume; it writes the public JWKS there too, and loreserver reads it
via `file://`. The key survives restarts and image rebuilds. Removing the volume
(`docker compose down -v`) regenerates it — loreserver picks up the new key on
the next token automatically.

## Quick start

    cp .env.example .env
    $EDITOR .env          # LORE_HOST, DEX_HOST, LORE_AUTH_HOST
    ./setup.sh            # renders caddy + lore configs
    docker compose up -d

Interactive login and refresh need UCS and do not work through Dex, so use the
device-flow helper `examples/get-token.sh` to get a token, then hand it to the CLI:

    TOKEN=$(./examples/get-token.sh)
    lore auth login --token-type lore --token "$TOKEN" lore://lore.yai.to:41337

## Notes

- **`[environment]` is undocumented upstream.** Re-check `lore/local.toml.tmpl`
  against the Lore source on upgrade (verified against v0.9.0).
- The QUIC cert path in `lore/local.toml.tmpl` follows Caddy's ACME (Let's
  Encrypt) layout; if you change ACME CA, update the directory name.
- Authorization is currently all-allow: `kaguya-auth` grants every requested
  resource to any verified Dex identity (both in the minted token's `resources`
  claim and in the ReBAC permission checks). Real per-repository policy — owners,
  groups — goes in `kaguya-auth`, not in loreserver config.
