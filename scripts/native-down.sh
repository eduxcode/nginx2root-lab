#!/usr/bin/env bash
# Stops the native target started by native-up.sh.
set -uo pipefail

PROJECT="$(cd "$(dirname "$0")/.." && pwd)"
PIDFILE="$PROJECT/.n2r/nginx/logs/nginx.pid"

if [ -s "$PIDFILE" ]; then
    pid="$(cat "$PIDFILE")"
    if kill -0 "$pid" 2>/dev/null; then
        kill "$pid"
        echo "[n2r] nginx stopped (pid $pid)"
    else
        echo "[n2r] pid $pid is not running"
    fi
    rm -f "$PIDFILE"
else
    echo "[n2r] nothing to stop (no pid file)"
fi
