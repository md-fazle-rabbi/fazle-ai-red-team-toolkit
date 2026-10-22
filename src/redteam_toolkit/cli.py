"""Command line entry point.

Exit codes: 0 means authorized or clean, 1 means a detector flagged an answer, 2 means
the Rules of Engagement file refused the request, 3 means a report or summary could
not be read.
"""

import argparse
import os
import sys
from collections.abc import Sequence
from pathlib import Path

import uvicorn

from redteam_toolkit.limits import RequestBudget
from redteam_toolkit.proxy import JsonlAudit, create_proxy_app
from redteam_toolkit.roe import SUITES, LoadedRoE, RoEError, RoEGate, Target, load_roe
from redteam_toolkit.scoring import (
    ReportError,
    format_scores,
    read_garak_report,
    score_attempts,
)
from redteam_toolkit.summary import (
    SummaryError,
    format_comparison,
    read_summary,
    summarize,
    summary_json,
)

EXIT_OK = 0
EXIT_FLAGGED = 1
EXIT_REFUSED = 2
EXIT_UNSCORABLE = 3
ENV_VAR = "REDTEAM_ROE_PATH"
# Why: the proxy forwards requests for whoever can reach it, so it only ever listens
# on this machine. There is deliberately no option to change the address.
PROXY_HOST = "127.0.0.1"
DEFAULT_PROXY_PORT = 8100
MIN_PORT = 1024
MAX_PORT = 65535


def _port(text: str) -> int:
    try:
        value = int(text)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(f"{text!r} is not a number") from exc
    if not MIN_PORT <= value <= MAX_PORT:
        raise argparse.ArgumentTypeError(
            f"port must be between {MIN_PORT} and {MAX_PORT}"
        )
    return value


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="redteam-toolkit",
        description=(
            "Authorized testing only. Every command that can send a request "
            "needs a Rules of Engagement file."
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

    proxy = sub.add_parser(
        "proxy",
        parents=[common],
        help="run a local gated proxy for tools that send their own requests",
    )
    proxy.add_argument("--target", required=True, help="target id from the file")
    proxy.add_argument("--suite", required=True, choices=SUITES)
    proxy.add_argument(
        "--port",
        type=_port,
        default=DEFAULT_PROXY_PORT,
        help=f"local port to listen on (default: {DEFAULT_PROXY_PORT})",
    )
    proxy.add_argument(
        "--audit",
        help="audit file to append to (default: a file under runs/)",
    )

    score = sub.add_parser(
        "score",
        help="score the answers in a garak report; sends nothing",
    )
    score.add_argument("--report", required=True, help="garak report (.report.jsonl)")
    score.add_argument(
        "--canary",
        action="append",
        default=[],
        help="a string the target must never repeat (repeat the option for more)",
    )
    score.add_argument(
        "--json",
        help="also write a JSON summary (counts and rates only) to this file",
    )

    compare = sub.add_parser(
        "compare",
        help="compare two run summaries side by side; sends nothing",
    )
    compare.add_argument("--before", required=True, help="summary JSON written earlier")
    compare.add_argument("--after", required=True, help="summary JSON to compare to it")
    return parser


def _resolve_path(arg: str | None) -> Path | None:
    # Why: an empty value counts as "not set". .env.example ships REDTEAM_ROE_PATH
    # empty, and an empty path must never be read as "the current directory".
    raw = arg or os.environ.get(ENV_VAR)
    return Path(raw) if raw else None


def _serve_proxy(
    loaded: LoadedRoE, gate: RoEGate, target: Target, args: argparse.Namespace
) -> None:
    # Why: the upstream is the target's base_url from the file, never an argument. The
    # proxy cannot be pointed anywhere the file does not authorize.
    audit_path = (
        Path(args.audit)
        if args.audit
        else Path("runs") / f"{gate.engagement_id}-{target.id}-{args.suite}-audit.jsonl"
    )
    audit_path.parent.mkdir(parents=True, exist_ok=True)
    app = create_proxy_app(
        gate,
        target_id=target.id,
        suite=args.suite,
        upstream_base=target.base_url,
        budget=RequestBudget(loaded.roe.limits),
        audit=JsonlAudit(audit_path),
    )
    sys.stdout.write(
        f"proxy: engagement={gate.engagement_id} target={target.id} "
        f"suite={args.suite} upstream={target.base_url} "
        f"listen=http://{PROXY_HOST}:{args.port} audit={audit_path}\n"
    )
    sys.stdout.flush()
    uvicorn.run(app, host=PROXY_HOST, port=args.port, log_level="warning")


def _score(args: argparse.Namespace) -> int:
    # Why: this only reads a local file and sends nothing, so it needs no Rules of
    # Engagement file. An empty report must never look clean, so it exits with 3.
    try:
        attempts = read_garak_report(Path(args.report))
    except (OSError, ReportError) as exc:
        sys.stderr.write(f"cannot score: {exc}\n")
        return EXIT_UNSCORABLE
    scores = score_attempts(attempts, canaries=args.canary)
    if not any(score.evaluated for score in scores):
        sys.stderr.write("cannot score: the report has no answered attempts\n")
        return EXIT_UNSCORABLE
    sys.stdout.write(format_scores(scores))
    summary = summarize(scores)
    sys.stdout.write(f"flagged attempts (any detector): {summary.flagged}\n")
    if args.json:
        try:
            Path(args.json).write_text(summary_json(summary), encoding="utf-8")
        except OSError as exc:
            sys.stderr.write(f"cannot write summary: {exc}\n")
            return EXIT_UNSCORABLE
    return EXIT_FLAGGED if summary.flagged else EXIT_OK


def _compare(args: argparse.Namespace) -> int:
    # Why: like score, this only reads local files. It prints both sides and never
    # decides which one is better, so it exits 0 whenever both files can be read.
    try:
        before = read_summary(Path(args.before))
        after = read_summary(Path(args.after))
    except (OSError, SummaryError) as exc:
        sys.stderr.write(f"cannot compare: {exc}\n")
        return EXIT_UNSCORABLE
    sys.stdout.write(format_comparison(before, after))
    return EXIT_OK


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.command == "score":
        return _score(args)
    if args.command == "compare":
        return _compare(args)
    try:
        loaded = load_roe(_resolve_path(args.file))
        gate = RoEGate(loaded)
        target = None
        if args.command in {"check", "proxy"}:
            target = gate.permit(
                target_id=args.target,
                suite=args.suite,
                url=getattr(args, "url", None),
            )
    except RoEError as exc:
        sys.stderr.write(f"refused: {exc}\n")
        return EXIT_REFUSED
    if args.command == "proxy" and target is not None:
        _serve_proxy(loaded, gate, target, args)
    elif args.command == "check":
        sys.stdout.write(
            f"permitted: engagement={gate.engagement_id} target={args.target} "
            f"suite={args.suite} roe_sha256={gate.sha256}\n"
        )
    else:
        sys.stdout.write(
            f"valid: engagement={gate.engagement_id} roe_sha256={gate.sha256}\n"
        )
    return EXIT_OK
