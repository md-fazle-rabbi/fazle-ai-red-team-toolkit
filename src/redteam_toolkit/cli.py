"""Command line entry point. Exit code 0 means authorized, 2 means refused."""

import argparse
import os
import sys
from collections.abc import Sequence
from pathlib import Path

from redteam_toolkit.roe import SUITES, RoEError, RoEGate, load_roe

EXIT_OK = 0
EXIT_REFUSED = 2
ENV_VAR = "REDTEAM_ROE_PATH"


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="redteam-toolkit",
        description=(
            "Authorized testing only. Every command needs a Rules of Engagement file."
        ),
    )
    sub = parser.add_subparsers(dest="command", required=True)

    common = argparse.ArgumentParser(add_help=False)
    common.add_argument(
        "--file",
        help=f"Rules of Engagement TOML file (default: the {ENV_VAR} variable)",
    )

    sub.add_parser(
        "validate",
        parents=[common],
        help="check that the file is valid",
    )
    check = sub.add_parser(
        "check",
        parents=[common],
        help="check that one target, suite and URL are authorized right now",
    )
    check.add_argument("--target", required=True, help="target id from the file")
    check.add_argument("--suite", required=True, choices=SUITES)
    check.add_argument("--url", help="full request URL to check against the target")
    return parser


def _resolve_path(arg: str | None) -> Path | None:
    # Why: an empty value counts as "not set". .env.example ships REDTEAM_ROE_PATH
    # empty, and an empty path must never be read as "the current directory".
    raw = arg or os.environ.get(ENV_VAR)
    return Path(raw) if raw else None


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        gate = RoEGate(load_roe(_resolve_path(args.file)))
        if args.command == "check":
            gate.permit(target_id=args.target, suite=args.suite, url=args.url)
    except RoEError as exc:
        sys.stderr.write(f"refused: {exc}\n")
        return EXIT_REFUSED
    if args.command == "check":
        sys.stdout.write(
            f"permitted: engagement={gate.engagement_id} target={args.target} "
            f"suite={args.suite} roe_sha256={gate.sha256}\n"
        )
    else:
        sys.stdout.write(
            f"valid: engagement={gate.engagement_id} roe_sha256={gate.sha256}\n"
        )
    return EXIT_OK
