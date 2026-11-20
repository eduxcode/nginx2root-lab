#!/usr/bin/env bash
# Demo de ponta a ponta: sobe tudo e executa a cadeia com aceleracao.
set -euo pipefail

cd "$(dirname "$0")/.."

./scripts/up.sh
echo
./scripts/attack.sh --accelerate
echo
docker compose ps -a
