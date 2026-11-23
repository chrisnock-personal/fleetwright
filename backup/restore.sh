#!/bin/bash
# Restore a FleetWright backup into this install (run from the repo directory, next to
# docker-compose.yml and .env):
#
#   backup/restore.sh <fleetwright-….tar.age> <age identity file>
#
# The identity is the private key matching BACKUP_AGE_RECIPIENTS (an age key file, or
# the SSH private key whose public key was used). It replaces the database and the
# HTTPS certificate with the backup's, so agents keep trusting the server, then starts
# FleetWright again. .env must have the FLEETWRIGHT_SECRET_KEY the backup was made
# with (or have it in FLEETWRIGHT_SECRET_KEY_PREVIOUS), or stored SSH keys and
# notification secrets can't be read.
set -euo pipefail
FILE=${1:?usage: backup/restore.sh <backup.tar.age> <age identity file>}
KEY=${2:?usage: backup/restore.sh <backup.tar.age> <age identity file>}
[ -f docker-compose.yml ] && [ -f .env ] || { echo "Run this from the FleetWright directory (with docker-compose.yml and .env)." >&2; exit 1; }
[ -r "$FILE" ] && [ -r "$KEY" ] || { echo "Can't read $FILE or $KEY" >&2; exit 1; }

if command -v docker >/dev/null && docker compose version >/dev/null 2>&1; then
    ENGINE=docker; COMPOSE=(docker compose)
else
    ENGINE=podman; COMPOSE=(podman-compose)
fi
set -a; . ./.env; set +a
PROJECT=${COMPOSE_PROJECT_NAME:-fleetwright}
NET=${PROJECT}_default
CERTS=${CERTS_VOLUME:-fleetwright_certs}
IMAGE=localhost/fleetwright-backup:latest
WORK=$(mktemp -d)
cleanup() {
    # The extracted certificate belongs to the image's user, which a rootless engine maps
    # to an id this account can't delete: empty it from inside a container first.
    $ENGINE run --rm --entrypoint sh -v "$WORK:/restore:z" "$IMAGE" -c 'rm -rf /restore/* /restore/.[!.]*' 2>/dev/null || true
    rm -rf "$WORK"
}
trap cleanup EXIT

echo "▸ building the backup image"
$ENGINE build -q -t "$IMAGE" backup >/dev/null
echo "▸ decrypting $(basename "$FILE")"
$ENGINE run --rm -i --entrypoint sh -v "$(realpath "$KEY"):/key:ro,z" -v "$WORK:/restore:z" "$IMAGE" \
    -c 'age -d -i /key | tar -x -C /restore' < "$FILE"
[ -s "$WORK/fleetwright.dump" ] || { echo "No database dump in that backup." >&2; exit 1; }
cat "$WORK/README" 2>/dev/null || true

echo "▸ stopping FleetWright (the database keeps running)"
"${COMPOSE[@]}" -p "$PROJECT" stop web worker >/dev/null 2>&1 || true
"${COMPOSE[@]}" -p "$PROJECT" up -d db >/dev/null
for _ in $(seq 1 30); do
    $ENGINE run --rm --entrypoint pg_isready --network "$NET" "$IMAGE" -q -h db && break
    sleep 2
done

echo "▸ restoring the database"
$ENGINE run --rm --entrypoint sh --network "$NET" -v "$WORK:/restore:ro,z" \
    -e PGHOST=db -e PGUSER="${POSTGRES_USER:-fleetwright}" -e PGPASSWORD="${POSTGRES_PASSWORD:-fleetwright}" \
    -e PGDATABASE="${POSTGRES_DB:-fleetwright}" "$IMAGE" \
    -c 'pg_restore --clean --if-exists --no-owner --single-transaction -d "$PGDATABASE" /restore/fleetwright.dump'

if [ -d "$WORK/certs" ]; then
    echo "▸ restoring the HTTPS certificate and key"
    # 10001: the fleetwright user in FleetWright's image
    $ENGINE run --rm --entrypoint sh -v "$CERTS:/certs:z" -v "$WORK:/restore:ro,z" "$IMAGE" \
        -c 'rm -rf /certs/* && cp -a /restore/certs/. /certs/ && chown -R 10001:10001 /certs && chmod 700 /certs'
fi

echo "▸ starting FleetWright"
"${COMPOSE[@]}" -p "$PROJECT" up -d web worker >/dev/null
echo "Restored. Agents reconnect by themselves; check the web log for a warning about FLEETWRIGHT_SECRET_KEY."
