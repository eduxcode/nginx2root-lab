#!/usr/bin/env bash
# End-to-end demo: brings everything up and runs the chain with the accelerator.
set -euo pipefail

cd "$(dirname "$0")/.."

./scripts/up.sh
echo
./scripts/attack.sh --accelerate
echo
docker compose ps -a
