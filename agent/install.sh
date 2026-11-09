#!/bin/sh
# FleetWright agent installer. Served by the FleetWright server, which fills in its
# address and, when it serves HTTPS itself, its certificate's public-key pin.
# Copy the exact command from Settings → Agents; it looks like:
#   curl -fsSL -k --pinnedpubkey 'sha256//…' https://fleetwright:8443/agent/install.sh | sudo sh -s -- <token>
set -eu

SERVER="@@SERVER@@"
PIN="@@PIN@@"
TOKEN="${1:-}"
INSECURE="${2:-}"
DIR=/opt/fleetwright-agent
CONF=/etc/fleetwright-agent

[ -n "$TOKEN" ] || { echo "usage: install.sh <enrolment token> [--insecure]" >&2; exit 2; }
[ "$(id -u)" -eq 0 ] || { echo "run this as root (sudo)" >&2; exit 1; }
case "$SERVER" in
    http://*)
        if [ "$INSECURE" != "--insecure" ]; then
            echo "Refusing to enrol over plain HTTP: the agent runs as root and its token and tasks" >&2
            echo "would cross the network unprotected. Serve FleetWright over HTTPS, or add --insecure." >&2
            exit 1
        fi ;;
esac

if [ -n "$PIN" ]; then
    # Only this server's key is accepted, whatever certificate authority signed it (or none).
    fetch() { curl -fsSL -k --pinnedpubkey "sha256//$PIN" "$@"; }
else
    fetch() { curl -fsSL "$@"; }
fi

echo "Installing python3 and python3-websockets…"
if command -v apt-get >/dev/null 2>&1; then
    DEBIAN_FRONTEND=noninteractive apt-get update -q >/dev/null
    DEBIAN_FRONTEND=noninteractive apt-get install -y -q python3 python3-websockets >/dev/null
elif command -v dnf >/dev/null 2>&1; then
    dnf install -y -q python3 python3-websockets >/dev/null
else
    echo "Neither apt nor dnf found: this distribution isn't supported" >&2
    exit 1
fi

echo "Fetching the agent from $SERVER…"
mkdir -p "$DIR"
install -d -m 700 "$CONF"
for f in fleetwright_agent.py pkgops.py; do
    fetch "$SERVER/agent/files/$f" -o "$DIR/$f.new"
    mv "$DIR/$f.new" "$DIR/$f"
done
chmod 755 "$DIR"
chmod 644 "$DIR"/*.py
fetch "$SERVER/agent/files/fleetwright-agent.service" -o /etc/systemd/system/fleetwright-agent.service

set -- enroll "$SERVER" "$TOKEN"
if [ -n "$PIN" ]; then
    # The agent trusts this exact certificate from now on (and the system CAs).
    fetch "$SERVER/agent/server.pem" -o "$CONF/server.pem"
    set -- "$@" --ca "$CONF/server.pem"
fi
[ "$INSECURE" = "--insecure" ] && set -- "$@" --insecure
python3 "$DIR/fleetwright_agent.py" "$@"

systemctl daemon-reload
systemctl enable --now fleetwright-agent >/dev/null 2>&1
systemctl restart fleetwright-agent
echo "The FleetWright agent is running: systemctl status fleetwright-agent"
