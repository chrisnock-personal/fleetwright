#!/bin/bash
# FleetWright's integration test: the whole stack, then real work on real hosts.
#
#   tests/integration/run.sh            (from the repo root; Docker or podman)
#
# 1. Builds and starts FleetWright (compose project "fwci", its own volumes).
# 2. Six SSH hosts from the load test's SSH farm, and the API smoke test against them.
# 3. Ubuntu 24.04 and Fedora 44 hosts running systemd: the agent is installed into each
#    with the real install command, scans with real apt and dnf, and fw (the CLI) turns
#    off Ubuntu's unattended-upgrades and installs one picked update on each.
# 4. Every page loads for a signed-in admin.
# Everything it started is removed at the end (KEEP=1 keeps it for a look). It writes
# .env, so outside CI it refuses to run in a checkout that already has one.
set -euo pipefail
cd "$(dirname "$0")/../.."

if docker compose version >/dev/null 2>&1; then
    E=docker; COMPOSE=(docker compose -p fwci)
    SYSTEMD=(--privileged --cgroupns=host -v /sys/fs/cgroup:/sys/fs/cgroup:rw --tmpfs /run --tmpfs /run/lock --tmpfs /tmp)
else
    E=podman; COMPOSE=(podman-compose -p fwci)
    SYSTEMD=(--systemd=always)
fi
NET=fwci_default
if [ -f .env ] && [ -z "${CI:-}" ]; then
    echo "There's a .env here: run this in a scratch copy of the repo, or in CI." >&2
    exit 2
fi

step() { echo; echo "=== $*"; }
fail() { echo "FAIL: $*" >&2; exit 1; }
rand() { python3 -c "import secrets; print(secrets.token_hex($1))"; }
tool() {   # a Python script from tests/ or the CLI, in the FleetWright image, on the stack's network
    $E run --rm -i --network $NET --env-file .env -e POSTGRES_HOST=db -e PYTHONPATH=/cli \
        -e FW_URL=https://web:8443 -e FW_TOKEN="${FW_TOKEN:-}" -e FW_FINGERPRINT="${FW_FINGERPRINT:-}" \
        -v "$PWD/tests:/tests:ro,z" -v "$PWD/tests/load:/load:ro,z" -v "$PWD/cli:/cli:ro,z" \
        localhost/fleetwright:latest python "$@"
}
fw() { tool -m fleetwright_cli "$@"; }
psql() { $E exec fwci_db_1 psql -U fleetwright -tAc "$1" 2>/dev/null || $E exec fwci-db-1 psql -U fleetwright -tAc "$1"; }
web_container() { $E ps --format '{{.Names}}' | grep -E '^fwci[-_]web[-_]1$'; }

cleanup() {
    status=$?
    if [ $status -ne 0 ]; then
        echo; echo "=== logs (it failed)"
        for c in web worker; do echo "--- $c"; $E logs "$($E ps -a --format '{{.Names}}' | grep -E "^fwci[-_]$c[-_]1$")" 2>&1 | tail -40 || true; done
        for h in fwci-ubuntu fwci-fedora; do echo "--- $h agent"; $E exec $h journalctl -u fleetwright-agent --no-pager -n 30 2>/dev/null || true; done
    fi
    if [ -z "${KEEP:-}" ]; then
        $E rm -f fwci-sshfarm fwci-ubuntu fwci-fedora >/dev/null 2>&1 || true
        "${COMPOSE[@]}" down -v >/dev/null 2>&1 || true
        $E volume rm -f fwci_pgdata fwci_certs >/dev/null 2>&1 || true
        rm -f .env
    fi
    exit $status
}
trap cleanup EXIT

step "1. Build and start FleetWright"
cat > .env <<EOF
FLEETWRIGHT_SECRET_KEY=$(rand 32)
FLEETWRIGHT_PUBLIC_URL=https://web:8443
FLEETWRIGHT_TLS_NAMES=127.0.0.1
HTTPS_EXPOSE=127.0.0.1:18943
HTTP_EXPOSE=127.0.0.1:18980
POSTGRES_PASSWORD=$(rand 12)
PGDATA_VOLUME=fwci_pgdata
CERTS_VOLUME=fwci_certs
FLEETWRIGHT_SCAN_INTERVAL_MIN=360
EOF
"${COMPOSE[@]}" up -d --build
(cd tests/load && $E build -q -f sshfarm/Containerfile -t localhost/fwci-sshfarm . >/dev/null)
$E build -q -f tests/integration/hosts/ubuntu.Containerfile -t localhost/fwci-ubuntu tests/integration/hosts >/dev/null
$E build -q -f tests/integration/hosts/fedora.Containerfile -t localhost/fwci-fedora tests/integration/hosts >/dev/null
for _ in $(seq 1 60); do curl -skf https://127.0.0.1:18943/healthz >/dev/null && break; sleep 2; done
curl -skf https://127.0.0.1:18943/healthz >/dev/null || fail "FleetWright didn't come up"

step "2. SSH hosts and the API smoke test"
tool /load/seed.py base > /tmp/fwci-base.txt
KEY=$(grep '^public key' /tmp/fwci-base.txt | cut -c12-); rm -f /tmp/fwci-base.txt
$E run -d --name fwci-sshfarm --network $NET -e "AUTHORIZED_KEY=$KEY" localhost/fwci-sshfarm 2200 6 >/dev/null
sleep 3
tool /load/seed.py ssh 6 fwci-sshfarm 2200
for _ in $(seq 1 60); do [ "$(psql "SELECT COUNT(*) FROM hosts WHERE last_scan_at IS NOT NULL")" = 6 ] && break; sleep 2; done
[ "$(psql "SELECT COUNT(*) FROM hosts WHERE last_scan_at IS NOT NULL AND last_error IS NULL")" = 6 ] \
    || fail "the SSH hosts weren't all scanned: $(psql "SELECT name || ': ' || COALESCE(last_error, 'not scanned') FROM hosts")"
FW_TOKEN=$($E exec "$(web_container)" python -c "
import asyncio
from fleetwright import db
from fleetwright.actions.core import Principal
from fleetwright.actions import tokens
async def m():
    await db.open_pool()
    print((await tokens.create_token(Principal(1, 'Load test', 'admin'), 'ci', 'admin', 1))['token'])
asyncio.run(m())")
export FW_TOKEN
tool /tests/integration/api_smoke.py https://web:8443 "$FW_TOKEN"

step "3. Agents on Ubuntu and Fedora hosts"
FW_FINGERPRINT=$(tool -c "
import json, ssl, urllib.request, os
ctx = ssl.create_default_context(); ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
req = urllib.request.Request('https://web:8443/api/v1/https', headers={'Authorization': 'Bearer ' + os.environ['FW_TOKEN']})
print(json.load(urllib.request.urlopen(req, context=ctx))['certificate']['sha256'])")
export FW_FINGERPRINT
fw whoami
ENROL=$(fw enrol create --label ci --tag ci-agent --json | python3 -c "import json,sys; print(json.load(sys.stdin)['token'])")
for os in ubuntu fedora; do
    $E run -d --name fwci-$os --hostname ci-$os --network $NET "${SYSTEMD[@]}" localhost/fwci-$os >/dev/null
done
sleep 8
for os in ubuntu fedora; do
    # To a file first: piped into sh, a failed download would look like success.
    $E exec fwci-$os sh -c "curl -fsSk -o /tmp/install.sh https://web:8443/agent/install.sh && sh /tmp/install.sh $ENROL" \
        | tail -2 || fail "the agent didn't install on ci-$os"
done
for _ in $(seq 1 90); do
    [ "$(psql "SELECT COUNT(*) FROM hosts WHERE name IN ('ci-ubuntu','ci-fedora') AND last_scan_at IS NOT NULL")" = 2 ] && break
    sleep 5
done
fw hosts list --tag ci-agent
[ "$(psql "SELECT COUNT(*) FROM hosts WHERE name IN ('ci-ubuntu','ci-fedora') AND agent_connected AND last_scan_at IS NOT NULL AND last_error IS NULL")" = 2 ] \
    || fail "both agents should be connected and have scanned"
[ "$(psql "SELECT auto_updates->0->>'installs' FROM hosts WHERE name = 'ci-ubuntu'")" = true ] \
    || fail "the Ubuntu host's unattended-upgrades wasn't detected"
fw run auto-off ci-ubuntu --yes --wait
[ "$(psql "SELECT auto_updates->0->>'installs' FROM hosts WHERE name = 'ci-ubuntu'")" = false ] \
    || fail "unattended-upgrades is still installing on the Ubuntu host"
for os in ubuntu fedora; do
    PKG=$(fw updates list ci-$os --json | python3 -c "import json,sys; u=json.load(sys.stdin)['updates']; print(u[0]['name'] if u else '')")
    if [ -z "$PKG" ]; then echo "ci-$os has nothing pending today; skipping its install"; continue; fi
    echo "installing $PKG on ci-$os"
    fw run apply ci-$os --pick "$PKG" --yes --wait --follow | tail -5
    [ "$(psql "SELECT COUNT(*) FROM package_changes c JOIN hosts h ON h.id = c.host_id WHERE h.name = 'ci-$os'")" -ge 1 ] \
        || fail "no package changes recorded on ci-$os"
done

step "4. Every page loads"
J=$(mktemp); C=(curl -sk -b "$J" -c "$J")
CSRF=$("${C[@]}" https://127.0.0.1:18943/login | grep -o 'name="csrf" value="[^"]*"' | sed 's/.*value="//; s/"//')
"${C[@]}" -o /dev/null -d "csrf=$CSRF&email=load@test.local&password=Load-test-pass-1" https://127.0.0.1:18943/login
HOST=$(psql "SELECT id FROM hosts WHERE name = 'ci-fedora'")
for p in / /hosts /hosts/$HOST /runs /runs/1 /schedules /schedules/policies/new /settings/keys /settings/groups \
         /settings/agents /settings/notifications /settings/backups /settings/users /settings/audit \
         /settings/https /account /api/v1/docs; do
    code=$("${C[@]}" -o /dev/null -w '%{http_code}' "https://127.0.0.1:18943$p")
    echo "$code $p"; [ "$code" = 200 ] || fail "$p answered $code"
done
rm -f "$J"
n=$($E logs "$(web_container)" 2>&1 | grep -c Traceback || true)
w=$($E logs "$($E ps --format "{{.Names}}" | grep -E "^fwci[-_]worker[-_]1$")" 2>&1 | grep -c Traceback || true)
[ "$w" = 0 ] || fail "$w tracebacks in the worker log"
[ "$n" = 0 ] || fail "$n tracebacks in the web log"

echo; echo "all passed"
