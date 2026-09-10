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

Log in interactively — `kaguya-auth` runs the device flow against Dex for you:

    lore auth login lore://lore.yai.to:41337      # opens a browser
    lore auth login --no-browser lore://lore.yai.to:41337   # prints the URL instead

This opens a Dex login page; approve it and the CLI stores the session.
`kaguya-auth` verifies the Dex identity and issues its own signed token.

**Refresh is not supported**: the `lore` client has no refresh call wired for
this flow, so when the token expires you log in again (there is nothing to renew
in the background). Tokens are issued with the Dex token's expiry.

loreserver trusts only `kaguya-auth` as issuer, so the old `get-token.sh` /
`--token-type lore` path (which hands the CLI a raw Dex token) no longer works:
loreserver rejects the Dex-signed identity token. Use `lore auth login`.
`examples/get-token.sh` is kept only as a reference for the Dex device flow.

## Authorization (ReBAC)

`kaguya-auth` enforces per-repository access from a SQLite store (in the
`auth-data` volume). Creating a repository records the creator as its **owner**;
the exchange then mints a token scoped to exactly the repositories the caller may
access, which is what loreserver's storage/revision authorization reads. A caller
with no grant on a repository cannot clone or push it.

Two roles: **owner** (access plus privileged operations — obliterate, admin,
migrate) and **member** (access: clone and push). Lore's storage authorizes on
the resource id alone, so there is no enforceable read-only role. Manage grants
and groups with the binary's admin subcommands:

    docker compose exec auth kaguya-auth grant  <subject> <urc-id> owner|member
    docker compose exec auth kaguya-auth revoke <subject> <urc-id>
    docker compose exec auth kaguya-auth group-add <group> <subject>
    docker compose exec auth kaguya-auth group-del <group> <subject>
    docker compose exec auth kaguya-auth ls <urc-id>

`<subject>` is a user id (the JWT `sub`) or `group:<name>`. `<urc-id>` is
`urc-<repository-id>` (the 32-hex id `lore` prints, e.g. from `lore status`).
Repositories created before ReBAC was enabled have no recorded owner; grant one
with `kaguya-auth grant <your-sub> <urc-id> owner`.

## Notes

- **`[environment]` is undocumented upstream.** Re-check `lore/local.toml.tmpl`
  against the Lore source on upgrade (verified against v0.9.0).
- The QUIC cert path in `lore/local.toml.tmpl` follows Caddy's ACME (Let's
  Encrypt) layout; if you change ACME CA, update the directory name.
