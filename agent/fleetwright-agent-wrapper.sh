#!/bin/sh
# FleetWright agent wrapper. Installed by install.sh and run by systemd;
# deliberately NOT part of the self-updating bundle, so a bad update cannot
# replace the code that knows how to undo it.
#
# Each attempt starts with an empty marker. The agent writes to that marker
# only after a WebSocket session has started and said hello. If it doesn't
# (import error, crash, can't connect) the previous *.prev files are restored
# and the agent is restarted. The server then sees the old agent say hello
# and fails the update task as a rollback.
#
# Overridable for tests / local overrides in a systemd drop-in:
#   FLEETWRIGHT_AGENT_DIR, FLEETWRIGHT_AGENT_PYTHON,
#   FLEETWRIGHT_AGENT_CONNECTED_MARKER, FLEETWRIGHT_AGENT_CONNECT_TIMEOUT,
#   FLEETWRIGHT_AGENT_CHECK_INTERVAL, FLEETWRIGHT_AGENT_MAX_EXITS,
#   FLEETWRIGHT_AGENT_RESTART_DELAY.
set -u

DIR=${FLEETWRIGHT_AGENT_DIR:-${AGENT_DIR:-/opt/fleetwright-agent}}
PYTHON=${FLEETWRIGHT_AGENT_PYTHON:-${AGENT_PYTHON:-/usr/bin/python3}}
MARKER=${FLEETWRIGHT_AGENT_CONNECTED_MARKER:-${FLEETWRIGHT_AGENT_MARKER:-${AGENT_CONNECTED_MARKER:-/run/fleetwright-agent/connected}}}
TIMEOUT=${FLEETWRIGHT_AGENT_CONNECT_TIMEOUT:-${FLEETWRIGHT_AGENT_TIMEOUT:-${AGENT_CONNECT_TIMEOUT:-300}}}
INTERVAL=${FLEETWRIGHT_AGENT_CHECK_INTERVAL:-0.5}
MAX_EXITS=${FLEETWRIGHT_AGENT_MAX_EXITS:-3}
RESTART_DELAY=${FLEETWRIGHT_AGENT_RESTART_DELAY:-10}
FILES="fleetwright_agent.py pkgops.py"

mkdir -p "$(dirname "$MARKER")" || exit 1

child=""

on_signal() {
    if [ -n "$child" ]; then
        kill -TERM "$child" 2>/dev/null || :
        wait "$child" 2>/dev/null || :
    fi
    exit 0
}
trap on_signal TERM INT HUP

# Milliseconds, so tests don't have to wait whole seconds. GNU date has %3N;
# other date implementations fall back to whole seconds.
now_ms() {
    stamp=$(date +%s%3N 2>/dev/null)
    case "$stamp" in
        ''|*[!0-9]*) stamp=$(date +%s)000 ;;
    esac
    echo "$stamp"
}

to_ms() {
    awk -v t="$1" 'BEGIN { printf "%.0f", t * 1000 }'
}

# A background child that has exited but not been waited for is a zombie:
# kill -0 still succeeds, so check /proc as well before calling it alive.
running() {
    kill -0 "$1" 2>/dev/null || return 1
    if [ -r "/proc/$1/stat" ]; then
        state=$(awk '{ sub(/^.*\) /, ""); print $1 }' "/proc/$1/stat" 2>/dev/null) || return 0
        [ "$state" != Z ] || return 1
    fi
    return 0
}

restore_prev() {
    for f in $FILES; do
        if [ ! -f "$DIR/$f.prev" ]; then
            echo "FleetWright: no $DIR/$f.prev to restore" >&2
            return 1
        fi
    done
    for f in $FILES; do
        tmp="$DIR/$f.restoring.$$"
        if ! cp "$DIR/$f.prev" "$tmp" || ! chmod 644 "$tmp" || ! mv "$tmp" "$DIR/$f"; then
            rm -f "$tmp"
            return 1
        fi
    done
    return 0
}

exits=0
while :; do
    : > "$MARKER"                 # an empty marker means "this start hasn't connected"
    "$PYTHON" "$DIR/fleetwright_agent.py" run &
    child=$!
    connected=0
    deadline=$(( $(now_ms) + $(to_ms "$TIMEOUT") ))

    while :; do
        if [ -s "$MARKER" ]; then
            connected=1
            break
        fi
        if ! running "$child"; then
            break
        fi
        if [ "$(now_ms)" -ge "$deadline" ]; then
            break
        fi
        sleep "$INTERVAL"
    done

    if [ "$connected" -eq 1 ]; then
        # A connected agent normally runs for days; don't poll it.
        wait "$child" 2>/dev/null || :
    else
        echo "FleetWright agent didn't connect in ${TIMEOUT}s; rolling back" >&2
        kill -TERM "$child" 2>/dev/null || :
        wait "$child" 2>/dev/null || :
    fi
    child=""
    exits=$((exits + 1))

    # No connection at all is already a failed update. An agent that connects
    # and then dies is allowed a few restarts (a transient crash needn't undo
    # a good update) before it counts as a bad one.
    if [ "$connected" -eq 0 ] || [ "$exits" -ge "$MAX_EXITS" ]; then
        if restore_prev; then
            echo "FleetWright agent rolled back; restarting the previous version" >&2
            exits=0
        else
            # Nothing to restore: don't keep trying to undo an update that has
            # no undo. systemd may still restart the service itself.
            echo "FleetWright agent couldn't roll back: no previous files" >&2
            exit 0
        fi
    fi
    sleep "$RESTART_DELAY"
done
