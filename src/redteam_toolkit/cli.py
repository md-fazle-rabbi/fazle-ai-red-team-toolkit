"""Command line entry point.

Exit codes: 0 means authorized, clean or passed, 1 means a detector flagged an answer
or a gate failed, 2 means the Rules of Engagement file refused the request, 3
means a report, summary or stats file could not be read or judged.
"""

import argparse
import os
import sys
from collections.abc import Sequence
from datetime import UTC, datetime
from pathlib import Path

import uvicorn

from redteam_toolkit.fairness import (
    DEFAULT_MAX_EQUALIZED_ODDS_DIFFERENCE,
    DEFAULT_MAX_PARITY_DIFFERENCE,
    DEFAULT_MIN_GROUP_SIZE,
    FairnessError,
    format_groups,
    read_fairness_summary,
)
from redteam_toolkit.fairness import evaluate as evaluate_fairness
from redteam_toolkit.limits import RequestBudget
from redteam_toolkit.load_gate import (
    DEFAULT_MAX_FAILURE_RATE,
    DEFAULT_MAX_P95_MS,
    DEFAULT_MIN_REQUESTS,
    LoadGateError,
    evaluate,
    read_locust_stats,
)
from redteam_toolkit.proxy import JsonlAudit, create_proxy_app
from redteam_toolkit.report import (
    ReportBuildError,
    RunInput,
    build_report,
    parse_run_spec,
)
from redteam_toolkit.robustness import (
    DEFAULT_EPSILON,
    DEFAULT_MAX_ACCURACY_DROP,
    DEFAULT_MIN_ROWS,
    RobustnessError,
    evaluate_robustness,
    format_points,
    read_robustness_summary,
)
from redteam_toolkit.roe import SUITES, LoadedRoE, RoEError, RoEGate, Target, load_roe
from redteam_toolkit.scoring import (
    ReportError,
    format_scores,
    read_answers_file,
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


def _positive(text: str) -> float:
    try:
        value = float(text)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(f"{text!r} is not a number") from exc
    if not value > 0:
        raise argparse.ArgumentTypeError("must be greater than zero")
    return value


def _rate(text: str) -> float:
    value = _positive(text)
    if value > 1:
        raise argparse.ArgumentTypeError("a rate must be between 0 and 1")
    return value


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
        help="score answers from a garak report or an answers file; sends nothing",
    )
    source = score.add_mutually_exclusive_group(required=True)
    source.add_argument("--report", help="garak report (.report.jsonl)")
    source.add_argument(
        "--answers",
        help='JSON lines file, one {"probe": ..., "answer": ...} object per line',
    )
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

    report = sub.add_parser(
        "report",
        parents=[common],
        help="write a Markdown report from run summaries; sends nothing",
    )
    report.add_argument(
        "--run",
        action="append",
        default=[],
        help="SUITE[:LABEL]=SUMMARY.json, repeat the option for more runs",
    )
    report.add_argument(
        "--fairness",
        help="fairness summary JSON to add as a group fairness section",
    )
    report.add_argument(
        "--robustness",
        help="robustness summary JSON to add as a robustness section",
    )
    report.add_argument("--out", required=True, help="Markdown file to write")

    gate = sub.add_parser(
        "load-gate",
        help="check a Locust stats file against thresholds; sends nothing",
    )
    gate.add_argument(
        "--stats", required=True, help="Locust stats file (NAME_stats.csv)"
    )
    gate.add_argument(
        "--max-p95-ms",
        type=_positive,
        default=DEFAULT_MAX_P95_MS,
        help=f"highest allowed p95 in milliseconds (default: {DEFAULT_MAX_P95_MS:g})",
    )
    gate.add_argument(
        "--max-failure-rate",
        type=_rate,
        default=DEFAULT_MAX_FAILURE_RATE,
        help=(
            "highest allowed share of failed requests "
            f"(default: {DEFAULT_MAX_FAILURE_RATE:g})"
        ),
    )
    gate.add_argument(
        "--min-requests",
        type=int,
        default=DEFAULT_MIN_REQUESTS,
        help=(
            "fewest requests a run needs to be judged "
            f"(default: {DEFAULT_MIN_REQUESTS})"
        ),
    )

    fair = sub.add_parser(
        "fairness-gate",
        help="check a group fairness summary against thresholds; sends nothing",
    )
    fair.add_argument("--summary", required=True, help="fairness summary JSON")
    fair.add_argument(
        "--max-parity-difference",
        type=_rate,
        default=DEFAULT_MAX_PARITY_DIFFERENCE,
        help=(
            "largest allowed gap in selection rate between groups "
            f"(default: {DEFAULT_MAX_PARITY_DIFFERENCE:g})"
        ),
    )
    fair.add_argument(
        "--max-equalized-odds-difference",
        type=_rate,
        default=DEFAULT_MAX_EQUALIZED_ODDS_DIFFERENCE,
        help=(
            "largest allowed gap in true or false positive rate between groups "
            f"(default: {DEFAULT_MAX_EQUALIZED_ODDS_DIFFERENCE:g})"
        ),
    )
    fair.add_argument(
        "--min-group-size",
        type=int,
        default=DEFAULT_MIN_GROUP_SIZE,
        help=f"fewest rows a group needs (default: {DEFAULT_MIN_GROUP_SIZE})",
    )

    robust = sub.add_parser(
        "robustness-gate",
        help="check a robustness summary against an accuracy drop; sends nothing",
    )
    robust.add_argument("--summary", required=True, help="robustness summary JSON")
    robust.add_argument(
        "--epsilon",
        type=_positive,
        default=DEFAULT_EPSILON,
        help=f"perturbation size to judge (default: {DEFAULT_EPSILON:g})",
    )
    robust.add_argument(
        "--max-accuracy-drop",
        type=_rate,
        default=DEFAULT_MAX_ACCURACY_DROP,
        help=(
            "largest allowed fall from clean accuracy "
            f"(default: {DEFAULT_MAX_ACCURACY_DROP:g})"
        ),
    )
    robust.add_argument(
        "--min-rows",
        type=int,
        default=DEFAULT_MIN_ROWS,
        help=f"fewest rows needed to judge (default: {DEFAULT_MIN_ROWS})",
    )
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
    # Engagement file. An empty input must never look clean, so it exits with 3.
    try:
        attempts = (
            read_answers_file(Path(args.answers))
            if args.answers
            else read_garak_report(Path(args.report))
        )
    except (OSError, ReportError) as exc:
        sys.stderr.write(f"cannot score: {exc}\n")
        return EXIT_UNSCORABLE
    scores = score_attempts(attempts, canaries=args.canary)
    if not any(score.evaluated for score in scores):
        sys.stderr.write("cannot score: the input has no answered attempts\n")
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


def _report(args: argparse.Namespace) -> int:
    # Why: this only reads local files and writes one report. A missing or invalid
    # Rules of Engagement file exits with 2, and a summary that cannot be read, or has
    # nothing evaluated, exits with 3 so an empty run never reads as clean.
    try:
        loaded = load_roe(_resolve_path(args.file))
    except RoEError as exc:
        sys.stderr.write(f"refused: {exc}\n")
        return EXIT_REFUSED
    try:
        runs = []
        for spec in args.run:
            suite, label, path = parse_run_spec(spec)
            runs.append(RunInput(label, suite, read_summary(Path(path))))
        fairness = read_fairness_summary(Path(args.fairness)) if args.fairness else None
        robustness = (
            read_robustness_summary(Path(args.robustness)) if args.robustness else None
        )
        text = build_report(
            loaded,
            runs,
            generated_at=datetime.now(UTC),
            fairness=fairness,
            robustness=robustness,
        )
        Path(args.out).write_text(text, encoding="utf-8")
    except (
        OSError,
        SummaryError,
        FairnessError,
        RobustnessError,
        ReportBuildError,
    ) as exc:
        sys.stderr.write(f"cannot report: {exc}\n")
        return EXIT_UNSCORABLE
    sys.stdout.write(f"report written: {args.out}\n")
    return EXIT_OK


def _load_gate(args: argparse.Namespace) -> int:
    # Why: this only reads a local file and sends nothing. A run that is empty or too
    # small to judge exits with 3, never 0, so it cannot look like a pass.
    try:
        stats = read_locust_stats(Path(args.stats))
        result = evaluate(
            stats,
            max_p95_ms=args.max_p95_ms,
            max_failure_rate=args.max_failure_rate,
            min_requests=args.min_requests,
        )
    except (OSError, LoadGateError) as exc:
        sys.stderr.write(f"cannot judge: {exc}\n")
        return EXIT_UNSCORABLE
    sys.stdout.write(
        f"requests={stats.requests} failures={stats.failures} "
        f"p95_ms={stats.p95_ms:g} requests_per_second={stats.requests_per_second:g}\n"
    )
    if result.passed:
        sys.stdout.write("load gate: pass\n")
        return EXIT_OK
    for reason in result.reasons:
        sys.stdout.write(f"load gate: fail, {reason}\n")
    return EXIT_FLAGGED


def _fairness_gate(args: argparse.Namespace) -> int:
    # Why: this only reads a local file and sends nothing. A summary that cannot be
    # judged exits with 3, never 0, so it cannot look like a pass.
    try:
        summary = read_fairness_summary(Path(args.summary))
        result = evaluate_fairness(
            summary,
            max_parity_difference=args.max_parity_difference,
            max_equalized_odds_difference=args.max_equalized_odds_difference,
            min_group_size=args.min_group_size,
        )
    except (OSError, FairnessError) as exc:
        sys.stderr.write(f"cannot judge: {exc}\n")
        return EXIT_UNSCORABLE
    sys.stdout.write(format_groups(summary))
    sys.stdout.write(
        f"demographic_parity_difference={result.parity_difference:.4f} "
        f"equalized_odds_difference={result.equalized_odds_difference:.4f}\n"
    )
    if result.passed:
        sys.stdout.write("fairness gate: pass\n")
        return EXIT_OK
    for reason in result.reasons:
        sys.stdout.write(f"fairness gate: fail, {reason}\n")
    return EXIT_FLAGGED


def _robustness_gate(args: argparse.Namespace) -> int:
    # Why: this only reads a local file and sends nothing. A summary that cannot be
    # judged exits with 3, never 0, so it cannot look like a pass.
    try:
        summary = read_robustness_summary(Path(args.summary))
        result = evaluate_robustness(
            summary,
            epsilon=args.epsilon,
            max_accuracy_drop=args.max_accuracy_drop,
            min_rows=args.min_rows,
        )
    except (OSError, RobustnessError) as exc:
        sys.stderr.write(f"cannot judge: {exc}\n")
        return EXIT_UNSCORABLE
    sys.stdout.write(format_points(summary))
    sys.stdout.write(
        f"epsilon={result.epsilon:g} accuracy_drop={result.accuracy_drop:.4f}\n"
    )
    if result.passed:
        sys.stdout.write("robustness gate: pass\n")
        return EXIT_OK
    for reason in result.reasons:
        sys.stdout.write(f"robustness gate: fail, {reason}\n")
    return EXIT_FLAGGED


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.command == "score":
        return _score(args)
    if args.command == "compare":
        return _compare(args)
    if args.command == "load-gate":
        return _load_gate(args)
    if args.command == "report":
        return _report(args)
    if args.command == "fairness-gate":
        return _fairness_gate(args)
    if args.command == "robustness-gate":
        return _robustness_gate(args)
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
