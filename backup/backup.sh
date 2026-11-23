#!/bin/sh
# FleetWright backups: the database (pg_dump) and the HTTPS certificate and key, in one
# tar encrypted with age to BACKUP_AGE_RECIPIENTS. Only public keys are here: whoever
# holds this server can make backups but not read them.
#
#   fleetwright-backup          daily at BACKUP_AT (UTC), and once at start if the
#                               newest backup is more than a day old
#   fleetwright-backup now      one backup, then exit
#
# Settings (from .env): BACKUP_AGE_RECIPIENTS (required; age1… or ssh-ed25519/ssh-rsa
# public keys, comma-separated), BACKUP_AT (default 03:30), BACKUP_KEEP (default 14).
# Each run writes its outcome to FleetWright's settings table (key backup_status).
set -eu
umask 077
DIR=/backups
AT=${BACKUP_AT:-03:30}
KEEP=${BACKUP_KEEP:-14}
export PGHOST=${POSTGRES_HOST:-db} PGUSER=${POSTGRES_USER:-fleetwright} \
       PGPASSWORD=${POSTGRES_PASSWORD:-fleetwright} PGDATABASE=${POSTGRES_DB:-fleetwright}

if [ -z "${BACKUP_AGE_RECIPIENTS:-}" ]; then
    echo "BACKUP_AGE_RECIPIENTS is not set: give one or more age (age1…) or SSH public keys," >&2
    echo "comma-separated. Keep the matching private key away from this server." >&2
    exit 2
fi
RECIPIENTS=$(mktemp)
echo "$BACKUP_AGE_RECIPIENTS" | tr ',' '\n' | sed 's/^ *//; s/ *$//' | grep -v '^$' > "$RECIPIENTS"

status() {   # status <ok:true|false> <file> <size> <message>
    json=$(printf '{"at": "%s", "ok": %s, "file": "%s", "size": %s, "kept": %s, "message": "%s", "schedule": "daily at %s UTC, keeping %s"}' \
        "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$1" "$2" "${3:-0}" "$(ls "$DIR"/fleetwright-*.tar.age 2>/dev/null | wc -l)" \
        "$(printf '%s' "$4" | tr '"\\\n' "'/ " | cut -c1-300)" "$AT" "$KEEP")
    echo "INSERT INTO settings (key, value) VALUES ('backup_status', :'v')
          ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value;" | psql -q -v v="$json" >/dev/null 2>&1 \
        || echo "couldn't record the backup status" >&2
}

backup() {
    ts=$(date -u +%Y%m%d-%H%M%S)
    name="fleetwright-$ts.tar.age"
    work=$(mktemp -d)
    err=$(mktemp)
    if {
        pg_dump -Fc -f "$work/fleetwright.dump" &&
        { [ ! -d /certs ] || cp -a /certs "$work/certs"; } &&
        printf 'FleetWright backup %s\npg_dump %s\n' "$ts" "$(pg_dump --version)" > "$work/README" &&
        tar -C "$work" -cf - . | age -R "$RECIPIENTS" -o "$DIR/$name.part" &&
        mv "$DIR/$name.part" "$DIR/$name"
    } 2>"$err"; then
        ls -1t "$DIR"/fleetwright-*.tar.age | tail -n +$((KEEP + 1)) | xargs -r rm -f
        size=$(stat -c %s "$DIR/$name")
        echo "$(date -u +%FT%TZ) backed up to $name ($size bytes)"
        status true "$name" "$size" ""
    else
        rm -f "$DIR/$name.part"
        echo "$(date -u +%FT%TZ) backup FAILED: $(cat "$err")" >&2
        status false "" 0 "$(tail -3 "$err")"
    fi
    rm -rf "$work" "$err"
}

if [ "${1:-}" = "now" ]; then
    backup
    exit 0
fi

echo "FleetWright backups: daily at $AT UTC, keeping $KEEP, to $DIR"
newest=$(ls -1t "$DIR"/fleetwright-*.tar.age 2>/dev/null | head -1)
if [ -z "$newest" ] || [ $(( $(date +%s) - $(stat -c %Y "$newest") )) -gt 86400 ]; then
    backup
fi
while true; do
    now=$(date -u +%s)
    next=$(date -u -d "$(date -u +%Y-%m-%d) $AT" +%s)
    [ "$next" -le "$now" ] && next=$((next + 86400))
    sleep $((next - now))
    backup
done
