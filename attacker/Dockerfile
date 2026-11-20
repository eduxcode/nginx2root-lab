# Atacante: Python 3 puro, sem dependencias externas.
FROM debian:bookworm-slim

RUN apt-get update \
 && apt-get install -y --no-install-recommends \
        python3 \
        ca-certificates \
        iproute2 \
        procps \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /lab
COPY . /lab

RUN chmod +x /lab/n2r

# O container fica vivo para receber `docker compose exec`.
CMD ["sleep", "infinity"]
