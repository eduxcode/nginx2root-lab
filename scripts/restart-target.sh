#!/usr/bin/env bash
# Sobe o alvo de novo depois do crash (SIGSEGV deixa o container parado).
#
#   ./scripts/restart-target.sh
#
# Com Docker: reaproveita o container existente e espera o healthcheck.
# Sem Docker: cai no modo nativo (foreground).
set -uo pipefail

PROJECT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$PROJECT"

if command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1; then
    if docker inspect n2r-target >/dev/null 2>&1; then
        echo "[n2r] reiniciando o container existente"
        docker compose start target >/dev/null
    else
        echo "[n2r] criando o container do alvo"
        docker compose up -d target
    fi

    echo -n "[n2r] aguardando o alvo ficar healthy"
    for _ in $(seq 1 40); do
        state="$(docker inspect -f '{{.State.Health.Status}}' n2r-target 2>/dev/null || echo starting)"

        if [ "$state" = "healthy" ]; then
            echo " ok"
            docker compose ps
            echo
            echo "[n2r] alvo no ar: https://127.0.0.1:8443"
            exit 0
        fi

        if [ "$state" = "unhealthy" ]; then
            echo " FALHOU"
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

echo "[n2r] Docker indisponivel; subindo no modo nativo (foreground)"
exec ./scripts/native-up.sh
