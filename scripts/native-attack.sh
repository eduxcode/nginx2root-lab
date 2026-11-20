#!/usr/bin/env bash
# Runs the PoC against the native target (no Docker).
#
#   ./scripts/native-attack.sh                 # crash included
#   ./scripts/native-attack.sh --no-accelerate # stages 1-6 only
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
