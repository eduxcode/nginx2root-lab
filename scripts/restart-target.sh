#!/usr/bin/env bash
# Brings the target back up after the crash (SIGSEGV leaves the container stopped).
#
#   ./scripts/restart-target.sh
#
# With Docker: reuses the existing container and waits for the healthcheck.
# Without Docker: falls back to native mode (foreground).
set -uo pipefail

PROJECT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$PROJECT"

if command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1; then
    if docker inspect n2r-target >/dev/null 2>&1; then
        echo "[n2r] restarting the existing container"
        docker compose start target >/dev/null
    else
        echo "[n2r] creating the target container"
        docker compose up -d target
    fi

    echo -n "[n2r] waiting for the target to become healthy"
    for _ in $(seq 1 40); do
        state="$(docker inspect -f '{{.State.Health.Status}}' n2r-target 2>/dev/null || echo starting)"

        if [ "$state" = "healthy" ]; then
            echo " ok"
            docker compose ps
            echo
            echo "[n2r] target up: https://127.0.0.1:8443"
            exit 0
        fi

        if [ "$state" = "unhealthy" ]; then
            echo " FAILED"
            docker compose logs --tail=40 target
            exit 1
        fi

        printf '.'
        sleep 1
    done

    echo " TIMEOUT"
    docker compose logs --tail=40 target
    exit 1
fi

echo "[n2r] Docker unavailable; starting in native mode (foreground)"
exec ./scripts/native-up.sh
