#!/usr/bin/env bash
# Generates a lab TLS key pair in target/ssl/ (optional, outside Docker).
set -euo pipefail

cd "$(dirname "$0")/.."
mkdir -p target/ssl

openssl req -x509 -newkey rsa:2048 -nodes -days 3650 \
    -subj "/CN=nginx2root-lab" \
    -keyout target/ssl/key.pem \
    -out target/ssl/cert.pem

chmod 600 target/ssl/key.pem
echo "[n2r] certificate generated in target/ssl/"
