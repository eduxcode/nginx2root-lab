#!/usr/bin/env bash
# Executa o PoC contra o alvo nativo (sem Docker).
#
#   ./scripts/native-attack.sh                 # crash incluido
#   ./scripts/native-attack.sh --no-accelerate # so os estagios 1-6
#   ./scripts/native-attack.sh --probe
set -uo pipefail

PROJECT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$PROJECT/attacker"

if [ "${1:-}" = "--probe" ]; then
    shift
    exec python3 -m poc probe --host 127.0.0.1 --port "${N2R_PORT:-8443}" "$@"
fi

if [ "${1:-}" = "--no-accelerate" ]; then
    shift
    exec python3 -m poc run --host 127.0.0.1 --port "${N2R_PORT:-8443}" "$@"
fi

exec python3 -m poc run --host 127.0.0.1 --port "${N2R_PORT:-8443}" \
    --accelerate "$@"
