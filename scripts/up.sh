#!/usr/bin/env bash
# Brings the lab up (build + containers) and waits for the target to be healthy.
set -euo pipefail

cd "$(dirname "$0")/.."

./tools/banner.sh

if [ ! -s target/src/nginx-1.31.8.tar.gz ]; then
    echo "[error] target/src/nginx-1.31.8.tar.gz not found" >&2
    exit 1
fi

echo
echo "[n2r] building images (the first run takes a few minutes)"
docker compose build

echo "[n2r] starting containers"
docker compose up -d

echo -n "[n2r] waiting for the target to become healthy"
healthy=0
for _ in $(seq 1 60); do
    state="$(docker inspect -f '{{.State.Health.Status}}' n2r-target 2>/dev/null || echo starting)"
    if [ "$state" = "healthy" ]; then
        healthy=1
        echo " ok"
        break
    fi
    if [ "$state" = "unhealthy" ]; then
        echo " FAILED"
        docker compose logs --tail=80 target
        exit 1
    fi
    echo -n "."
    sleep 1
done

if [ "$healthy" -ne 1 ]; then
    echo " TIMEOUT"
    docker compose logs --tail=80 target
    exit 1
fi

echo
docker compose ps
echo
echo "[n2r] target:  https://127.0.0.1:8443  (HTTP/2, TLS)"
echo "[n2r] next:    ./scripts/attack.sh --accelerate"
