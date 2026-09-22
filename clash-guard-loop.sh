#!/bin/bash
# Compatibility loop. Prefer the LaunchAgent in the README for normal use.

set -u

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P) || exit 1
INTERVAL=${CLASH_GUARD_INTERVAL:-60}
LOCK_ROOT=${TMPDIR:-/tmp}
LOCK_DIR="${LOCK_ROOT%/}/clash-guard-loop.$(id -u).lock"

case "$INTERVAL" in
    ''|*[!0-9]*) echo "CLASH_GUARD_INTERVAL must be a positive integer" >&2; exit 2 ;;
esac
if [ "$INTERVAL" -lt 1 ]; then
    echo "CLASH_GUARD_INTERVAL must be at least 1" >&2
    exit 2
fi

acquire_lock() {
    if mkdir -m 700 "$LOCK_DIR" 2>/dev/null; then
        printf '%s\n' "$$" >"$LOCK_DIR/pid"
        return 0
    fi

    old_pid=''
    if [ -r "$LOCK_DIR/pid" ]; then
        IFS= read -r old_pid <"$LOCK_DIR/pid"
    fi
    case "$old_pid" in
        ''|*[!0-9]*) ;;
        *)
            if kill -0 "$old_pid" 2>/dev/null; then
                return 1
            fi
            ;;
    esac

    stale_dir="${LOCK_DIR}.stale.$$"
    if mv "$LOCK_DIR" "$stale_dir" 2>/dev/null; then
        rm -f "$stale_dir/pid"
        rmdir "$stale_dir" 2>/dev/null || true
    fi
    mkdir -m 700 "$LOCK_DIR" 2>/dev/null || return 1
    printf '%s\n' "$$" >"$LOCK_DIR/pid"
}

cleanup() {
    saved_pid=''
    if [ -r "$LOCK_DIR/pid" ]; then
        IFS= read -r saved_pid <"$LOCK_DIR/pid"
    fi
    if [ "$saved_pid" = "$$" ]; then
        rm -f "$LOCK_DIR/pid"
        rmdir "$LOCK_DIR" 2>/dev/null || true
    fi
}

if ! acquire_lock; then
    exit 0
fi
trap cleanup EXIT
trap 'exit 0' HUP INT TERM

while :; do
    /usr/bin/python3 "$SCRIPT_DIR/clash-guard.py"
    sleep "$INTERVAL"
done
