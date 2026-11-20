#!/usr/bin/env bash
# Derruba o laboratorio e remove as redes/containers do compose.
set -euo pipefail

cd "$(dirname "$0")/.."
docker compose down -v --remove-orphans
