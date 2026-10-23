# Sourced by ops/update.sh and ops/install.sh: the kaguya-specific parts.

STACK=kaguya
HEALTH_TIMEOUT=180

# Gitignored files needed to rebuild the host (.env is always included).
CONFIG_FILES="caddy/Caddyfile lore/local.toml"

# Host schedule (local time). Staggered across the fleet: iroha 02:00,
# kaguya 03:00, yachiyo 04:00; reboots 05:00 / 05:20 / 05:40.
UPDATE_ON_CALENDAR="*-*-* 03:00:00"
REBOOT_TIME="05:20"

stack_backup() {
    # Signing key, ReBAC store, and repository data. Stop the writers so the
    # copies are consistent; the following `docker compose up -d` restarts them.
    # lore-data grows with your repositories: this backup (and the downtime it
    # takes) grows with it.
    docker compose stop lore auth &&
        backup_volume auth /keys "$1/auth-keys.tgz" &&
        backup_volume auth /data "$1/auth-data.tgz" &&
        backup_volume lore /data "$1/lore-data.tgz"
}

stack_health() {
    # The web frontend through Caddy; lore/auth state is covered by the
    # container checks in update.sh (auth's healthcheck gates on the JWKS).
    probe "$LORE_WEB_HOST" /healthz
}
