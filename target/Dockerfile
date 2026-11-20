# Alvo vulneravel: nginx 1.31.8 compilado do fonte com o patch de
# instrumentacao do laboratorio (apenas logs + gancho de aceleracao).
FROM debian:bookworm-slim AS build

ARG NGINX_VERSION=1.31.8
ARG NGINX_SHA256=0652b760b3b772d2ec17b47c2fc15d9a95e6fe35cd5b877eadc1a62d9bc75af1

RUN apt-get update \
 && apt-get install -y --no-install-recommends \
        build-essential \
        ca-certificates \
        libpcre2-dev \
        zlib1g-dev \
        libssl-dev \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /usr/src

COPY src/nginx-1.31.8.tar.gz /usr/src/nginx.tar.gz
COPY n2r-instrument.patch /usr/src/n2r-instrument.patch

RUN echo "${NGINX_SHA256}  /usr/src/nginx.tar.gz" | sha256sum -c - \
 && tar xzf nginx.tar.gz \
 && cd nginx-${NGINX_VERSION} \
 && patch -p1 < /usr/src/n2r-instrument.patch \
 && ./configure \
        --prefix=/etc/nginx \
        --sbin-path=/usr/sbin/nginx \
        --conf-path=/etc/nginx/nginx.conf \
        --pid-path=/run/nginx.pid \
        --error-log-path=/var/log/nginx/error.log \
        --http-log-path=/var/log/nginx/access.log \
        --with-http_ssl_module \
        --with-http_v2_module \
        --with-debug \
        --with-cc-opt="-O2 -g" \
 && make -j"$(nproc)" \
 && make install


FROM debian:bookworm-slim

RUN apt-get update \
 && apt-get install -y --no-install-recommends \
        libpcre2-8-0 \
        zlib1g \
        libssl3 \
        openssl \
        curl \
        procps \
 && rm -rf /var/lib/apt/lists/* \
 && useradd --system --no-create-home --shell /usr/sbin/nologin nginx \
 && mkdir -p /var/log/nginx /var/cache/nginx /srv/http /etc/nginx/ssl

COPY --from=build /usr/sbin/nginx /usr/sbin/nginx
COPY --from=build /etc/nginx/mime.types /etc/nginx/mime.types
COPY nginx.conf /etc/nginx/nginx.conf
COPY entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh

EXPOSE 8443

HEALTHCHECK --interval=3s --timeout=2s --start-period=5s --retries=10 \
    CMD curl -ksS -o /dev/null https://127.0.0.1:8443/ || exit 1

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
