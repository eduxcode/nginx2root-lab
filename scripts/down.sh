#!/usr/bin/env bash
# Tears down the lab and removes the compose networks/containers.
set -euo pipefail

cd "$(dirname "$0")/.."
docker compose down -v --remove-orphans
