#!/usr/bin/env bash
# Derruba o alvo nativo iniciado por native-up.sh.
set -uo pipefail

PROJECT="$(cd "$(dirname "$0")/.." && pwd)"
PIDFILE="$PROJECT/.n2r/nginx/logs/nginx.pid"

if [ -s "$PIDFILE" ]; then
    pid="$(cat "$PIDFILE")"
    if kill -0 "$pid" 2>/dev/null; then
        kill "$pid"
        echo "[n2r] nginx parado (pid $pid)"
    else
        echo "[n2r] pid $pid nao esta rodando"
    fi
    rm -f "$PIDFILE"
else
    echo "[n2r] nada para parar (sem pid file)"
fi
