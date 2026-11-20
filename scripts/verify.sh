#!/usr/bin/env bash
# Shows the crash evidence: [n2r] lines, signal and worker restart.
set -uo pipefail

PROJECT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$PROJECT"

PATTERN='\[n2r\]|exited on signal|start worker process|AddressSanitizer|negative-size-param'

if command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1; then
    echo "[n2r] source: docker compose logs target"
    docker compose logs --no-log-prefix --tail=500 target \
        | grep -aE "$PATTERN" \
        | tail -n 40
    echo
    echo "[n2r] state: $(docker inspect -f '{{.State.Status}} exit={{.State.ExitCode}}' n2r-target 2>/dev/null)"
    exit 0
fi

LOG="${N2R_LOG:-$PROJECT/.n2r/nginx/logs/error.log}"
if [ -s "$LOG" ]; then
    echo "[n2r] source: $LOG"
    grep -aE "$PATTERN" "$LOG" | tail -n 40
    exit 0
fi

echo "[n2r] no log found (start the target first)" >&2
exit 1
