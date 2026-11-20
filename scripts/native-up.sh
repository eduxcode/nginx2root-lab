#!/usr/bin/env bash
# Starts the nginx 1.31.8 target WITHOUT Docker (native mode).
#
# Builds the vendored source, generates TLS and huge.bin, and runs nginx in
# the foreground. The target log is written to this terminal (stderr).
#
# Variables:
#   N2R_PORT=8443     TLS port
#   N2R_SINGLE=1      master_process off (the worker IS the main
#                     process: the target really goes down on crash)
#   N2R_ASAN=1        builds with AddressSanitizer (memory-corruption
#                     evidence; uses .n2r-asan/)
#
# Usage: ./scripts/native-up.sh
set -euo pipefail

PROJECT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$PROJECT"

VERSION=1.31.8
PORT="${N2R_PORT:-8443}"
SINGLE="${N2R_SINGLE:-0}"
ASAN="${N2R_ASAN:-0}"

if [ "$ASAN" = "1" ]; then
    ROOT="$PROJECT/.n2r-asan"
    EXTRA_CFG=(--with-cc-opt="-O1 -fsanitize=address -fno-omit-frame-pointer"
               --with-ld-opt="-fsanitize=address")
else
    ROOT="$PROJECT/.n2r"
    EXTRA_CFG=(--with-cc-opt="-O2 -g")
fi

BUILD="$ROOT/build"
PREFIX="$ROOT/nginx"
SRC="$BUILD/nginx-$VERSION"

die() { echo "[erro] $*" >&2; exit 1; }

for tool in gcc make perl openssl python3 patch tar; do
    command -v "$tool" >/dev/null 2>&1 || die "missing tool: $tool"
done

[ -s "target/src/nginx-$VERSION.tar.gz" ] \
    || die "target/src/nginx-$VERSION.tar.gz not found"

mkdir -p "$BUILD" "$PREFIX"/conf "$PREFIX"/logs "$PREFIX"/html \
         "$PREFIX"/ssl "$PREFIX"/cache/client "$PREFIX"/cache/proxy \
         "$PREFIX"/cache/fastcgi "$PREFIX"/cache/uwsgi "$PREFIX"/cache/scgi

# ------------------------------------------------------------------
# build (once per variant)
# ------------------------------------------------------------------
if [ ! -x "$SRC/objs/nginx" ]; then
    if [ ! -d "$SRC" ]; then
        echo "[n2r] extracting nginx $VERSION"
        tar xzf "target/src/nginx-$VERSION.tar.gz" -C "$BUILD"
        ( cd "$SRC" && patch -p1 < "$PROJECT/target/n2r-instrument.patch" )
    fi

    echo "[n2r] configuring and building (1-2 minutes)"
    CONFIG_ARGS=(
        --prefix="$PREFIX"
        --sbin-path="$PREFIX/sbin/nginx"
        --conf-path="$PREFIX/conf/nginx.conf"
        --pid-path="$PREFIX/logs/nginx.pid"
        --error-log-path="$PREFIX/logs/error.log"
        --http-log-path="$PREFIX/logs/access.log"
        --with-http_ssl_module
        --with-http_v2_module
        --with-debug
    )
    CONFIG_ARGS+=("${EXTRA_CFG[@]}")

    # Without the PCRE2 headers the rewrite module does not build.
    if [ ! -f /usr/include/pcre2.h ]; then
        echo "[n2r] PCRE2 missing: building without rewrite/gzip (does not affect the bug)"
        CONFIG_ARGS+=(--without-http_rewrite_module --without-http_gzip_module)
    fi

    (
        cd "$SRC"
        ./configure "${CONFIG_ARGS[@]}"
        make -j"$(nproc)"
    )
fi

# ------------------------------------------------------------------
# TLS and large object
# ------------------------------------------------------------------
if [ ! -s "$PREFIX/ssl/cert.pem" ] || [ ! -s "$PREFIX/ssl/key.pem" ]; then
    echo "[n2r] generating self-signed certificate"
    openssl req -x509 -newkey rsa:2048 -nodes -days 3650 \
        -subj "/CN=nginx2root-lab" \
        -keyout "$PREFIX/ssl/key.pem" \
        -out "$PREFIX/ssl/cert.pem" >/dev/null 2>&1
    chmod 600 "$PREFIX/ssl/key.pem"
fi

if [ ! -s "$PREFIX/html/huge.bin" ]; then
    echo "[n2r] generating html/huge.bin (64 MiB)"
    head -c 67108864 /dev/zero > "$PREFIX/html/huge.bin"
fi

# ------------------------------------------------------------------
# configuration (absolute paths)
# ------------------------------------------------------------------
MASTER_LINE=""
if [ "$SINGLE" = "1" ]; then
    MASTER_LINE="master_process off;"
fi

cat > "$PREFIX/conf/nginx.conf" <<EOF
worker_processes 1;
daemon off;
$MASTER_LINE

error_log stderr info;
error_log $PREFIX/logs/error.log info;
pid $PREFIX/logs/nginx.pid;

events {
    worker_connections 1024;
}

http {
    default_type application/octet-stream;
    access_log off;

    client_body_temp_path $PREFIX/cache/client;
    proxy_temp_path       $PREFIX/cache/proxy;
    fastcgi_temp_path     $PREFIX/cache/fastcgi;
    uwsgi_temp_path       $PREFIX/cache/uwsgi;
    scgi_temp_path        $PREFIX/cache/scgi;

    server {
        listen $PORT ssl;
        http2 on;
        server_name _;

        ssl_certificate     $PREFIX/ssl/cert.pem;
        ssl_certificate_key $PREFIX/ssl/key.pem;
        ssl_protocols       TLSv1.2 TLSv1.3;

        sendfile            on;
        sendfile_max_chunk  16m;
        http2_chunk_size    16k;
        output_buffers      8 1m;

        root $PREFIX/html;

        location / {
        }
    }
}
EOF

echo
mode="normal"
[ "$SINGLE" = "1" ] && mode="single-process (the target goes down on crash)"
[ "$ASAN" = "1" ] && mode="$mode + AddressSanitizer"
echo "[n2r] native target at https://127.0.0.1:$PORT  (HTTP/2, TLS)"
echo "[n2r] mode: $mode"
echo "[n2r] target log in this terminal — Ctrl-C to stop"
echo "[n2r] attack from the other terminal: ./scripts/native-attack.sh"
echo

if [ "$ASAN" = "1" ]; then
    export ASAN_OPTIONS="detect_leaks=0:abort_on_error=1:symbolize=1"
fi

exec "$SRC/objs/nginx" -p "$PREFIX" -c "$PREFIX/conf/nginx.conf"
