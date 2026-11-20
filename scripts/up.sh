#!/usr/bin/env bash
# Sobe o laboratorio (build + containers) e espera o alvo ficar healthy.
set -euo pipefail

cd "$(dirname "$0")/.."

./tools/banner.sh

if [ ! -s target/src/nginx-1.31.8.tar.gz ]; then
    echo "[erro] target/src/nginx-1.31.8.tar.gz nao encontrado" >&2
    exit 1
fi

echo
echo "[n2r] construindo imagens (a primeira vez leva alguns minutos)"
docker compose build

echo "[n2r] subindo containers"
docker compose up -d

echo -n "[n2r] aguardando o alvo ficar healthy"
healthy=0
for _ in $(seq 1 60); do
    state="$(docker inspect -f '{{.State.Health.Status}}' n2r-target 2>/dev/null || echo starting)"
    if [ "$state" = "healthy" ]; then
        healthy=1
        echo " ok"
        break
    fi
    if [ "$state" = "unhealthy" ]; then
        echo " FALHOU"
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
echo "[n2r] alvo:    https://127.0.0.1:8443  (HTTP/2, TLS)"
echo "[n2r] proximo: ./scripts/attack.sh --accelerate"
