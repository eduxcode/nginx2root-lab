#!/usr/bin/env bash
# Runs the PoC inside the attacker container and shows the target log.
#
#   ./scripts/attack.sh                 # full chain + crash stage
#   ./scripts/attack.sh --no-accelerate # stops at stage 6 (no crash)
#   ./scripts/attack.sh --probe         # fingerprint only
set -uo pipefail

cd "$(dirname "$0")/.."

if [ "${1:-}" = "--probe" ]; then
    shift
    docker compose exec -T attacker ./n2r probe --host target "$@"
    exit $?
fi

rc=0
if [ "${1:-}" = "--no-accelerate" ]; then
    shift
    docker compose exec -T attacker ./n2r run --host target "$@" || rc=$?
else
    docker compose exec -T attacker ./n2r run --host target --accelerate "$@" || rc=$?
fi

echo
echo "─────────────────────────── target log ──────────────────────────"
docker compose logs --no-log-prefix --tail=400 target \
    | grep -aE '\[n2r\]|exited on signal|start worker process|signal 11' \
    | tail -n 24 \
    | sed -E 's/(\[n2r\])/\x1b[38;5;221m\1\x1b[0m/; s/(exited on signal.*|signal 11.*)/\x1b[38;5;203m\1\x1b[0m/'
echo "─────────────────────────────────────────────────────────────────"

state="$(docker inspect -f '{{.State.Status}} exit={{.State.ExitCode}}' n2r-target 2>/dev/null || true)"
if [ -n "$state" ]; then
    echo "target state: $state"
    if docker inspect -f '{{.State.Status}}' n2r-target 2>/dev/null | grep -qx exited; then
        echo "the target container stopped: the nginx process really died."
    else
        echo "the container is still up because the master respawned the worker."
        echo "start with N2R_SINGLE=1 so the target goes down (Compose default)."
    fi
fi

exit "$rc"
