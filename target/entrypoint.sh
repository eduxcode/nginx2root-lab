#!/bin/sh
# Prepares TLS and the large object, then hands PID 1 to nginx.
set -eu

mkdir -p /var/log/nginx /var/cache/nginx /etc/nginx/ssl /srv/http

if [ ! -s /etc/nginx/ssl/cert.pem ] || [ ! -s /etc/nginx/ssl/key.pem ]; then
    echo "[n2r] generating lab self-signed certificate"
    openssl req -x509 -newkey rsa:2048 -nodes -days 3650 \
        -subj "/CN=nginx2root-lab" \
        -keyout /etc/nginx/ssl/key.pem \
        -out /etc/nginx/ssl/cert.pem >/dev/null 2>&1
    chmod 600 /etc/nginx/ssl/key.pem
fi

if [ ! -s /srv/http/huge.bin ]; then
    echo "[n2r] generating /srv/http/huge.bin (64 MiB)"
    head -c 67108864 /dev/zero > /srv/http/huge.bin
fi

# the worker runs as the nginx user: it must write logs and temp paths
chown -R nginx:nginx /var/cache/nginx /var/log/nginx /srv/http 2>/dev/null || true

if [ "${N2R_SINGLE:-0}" = "1" ]; then
    echo "[n2r] single-process mode: the crash takes the container down"
    exec /usr/sbin/nginx -g 'master_process off;' -c /etc/nginx/nginx.conf
fi

echo "[n2r] starting instrumented nginx 1.31.8"
exec /usr/sbin/nginx -c /etc/nginx/nginx.conf
