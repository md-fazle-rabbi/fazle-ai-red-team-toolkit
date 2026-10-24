"""Build a Markdown report from a Rules of Engagement file and scored results.

The report holds counts, rates and framework mappings only. Run summaries and the
fairness summary never carry prompt or answer text, so neither does the report. A run
with nothing evaluated cannot be reported, and neither can a fairness summary that is
too thin to judge, because a table of zeros would look like a clean result.
"""

from __future__ import annotations

import re
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import datetime
from typing import Final

from redteam_toolkit.fairness import (
    DEFAULT_MAX_EQUALIZED_ODDS_DIFFERENCE,
    DEFAULT_MAX_PARITY_DIFFERENCE,
    FairnessError,
    FairnessSummary,
    evaluate,
)
from redteam_toolkit.roe import SUITES, LoadedRoE
from redteam_toolkit.summary import CAVEAT, RunSummary
from redteam_toolkit.threat_map import (
    ATLAS_RELEASE,
    ATLAS_TECHNIQUES,
    OWASP_LLM,
    OWASP_LLM_EDITION,
    mapping_for,
)

_LABEL: Final = re.compile(r"[A-Za-z0-9][A-Za-z0-9 ._-]{0,39}")
DEFAULT_LABEL: Final = "run"
FAIRNESS_SUITE: Final = "bias"

RUN_LIMITATIONS: Final[tuple[str, ...]] = (
    CAVEAT,
    "The flagged rate is not a bypass rate for the target. The detectors do not "
    "judge whether an answer was helpful, harmful or correct.",
)
COMMON_LIMITATIONS: Final[tuple[str, ...]] = (
    "Results describe the targets named above during the stated window and nothing "
    "else. A result against a local stub says nothing about another system.",
    "The STRIDE entries are the author's judgement. The ATLAS and OWASP entries are "
    "copied from the releases named in the mapping section and may have changed since.",
    "This report comes from the toolkit's own checks. It is not an audit, a "
    "certification or proof that no weakness exists.",
    "The report holds counts and rates only. It contains no prompt text and no "
    "answer text.",
)
FAIRNESS_LIMITATIONS: Final[tuple[str, ...]] = (
    "The fairness figures come from synthetic data and a stand-in model. They say "
    "nothing about any real system or any real person.",
    "The fairness limits are policy values I chose, not measured ones. A small gap "
    "does not show a system is fair, and a large gap does not say why it exists.",
)
# Kept as one tuple for callers that want every fixed run limitation.
LIMITATIONS: Final[tuple[str, ...]] = RUN_LIMITATIONS + COMMON_LIMITATIONS


class ReportBuildError(ValueError):
    """The report cannot be built from the inputs given."""


@dataclass(frozen=True, slots=True)
class RunInput:
    label: str
    suite: str
    summary: RunSummary


def parse_run_spec(text: str) -> tuple[str, str, str]:
    """Split 'SUITE[:LABEL]=PATH' into (suite, label, path)."""
    head, sep, path = text.partition("=")
    if not sep or not path:
        raise ReportBuildError(f"{text!r} is not in the form SUITE[:LABEL]=PATH")
    suite, _, label = head.partition(":")
    if suite not in SUITES:
        raise ReportBuildError(f"{suite!r} is not a known suite")
    label = label or DEFAULT_LABEL
    if not _LABEL.fullmatch(label):
        raise ReportBuildError(f"{label!r} is not a valid label")
    return suite, label, path


def _cell(text: str) -> str:
    # Why: probe names come from a file. Keep them from breaking out of a table cell.
    return " ".join(text.split()).replace("|", "\\|")


def _percent(rate: float | None) -> str:
    return "n/a" if rate is None else f"{rate * 100:.1f}%"


def _rate(rate: float | None) -> str:
    return "n/a" if rate is None else f"{rate:.4f}"


def _check(
    loaded: LoadedRoE, runs: Sequence[RunInput], fairness: FairnessSummary | None
) -> None:
    if not runs and fairness is None:
        raise ReportBuildError("no runs were given")
    allowed = loaded.roe.allowed_suites
    if fairness is not None and FAIRNESS_SUITE not in allowed:
        raise ReportBuildError(
            f"suite {FAIRNESS_SUITE!r} is not in allowed_suites of the engagement"
        )
    seen: set[tuple[str, str]] = set()
    for run in runs:
        if run.suite not in allowed:
            raise ReportBuildError(
                f"suite {run.suite!r} is not in allowed_suites of the engagement"
            )
        key = (run.suite, run.label)
        if key in seen:
            raise ReportBuildError(
                f"two runs share the suite {run.suite!r} and the label {run.label!r}"
            )
        seen.add(key)
        if run.summary.evaluated == 0:
            raise ReportBuildError(
                f"the {run.label!r} run for {run.suite!r} has no evaluated attempts"
            )


def _engagement(loaded: LoadedRoE) -> list[str]:
    roe = loaded.roe
    lines = [
        "## Engagement",
        "",
        f"- Engagement id: {roe.engagement_id}",
        f"- Client: {roe.client.name}",
        f"- Authorized by: {roe.authorized_by.name} ({roe.authorized_by.role})",
        f"- Operator: {roe.operator.name} ({roe.operator.role})",
        f"- Window: {roe.window.start.isoformat()} to {roe.window.end.isoformat()}",
        f"- Authorization: {roe.authorization.kind}, {roe.authorization.reference}",
    ]
    if roe.authorization.sha256 is not None:
        lines.append(f"- Signed document SHA-256: {roe.authorization.sha256}")
    lines.append(f"- Rules of Engagement file SHA-256: {loaded.sha256}")
    lines.append(
        f"- Limits: {roe.limits.requests_per_minute} per minute, "
        f"{roe.limits.total_requests} in total, {roe.limits.concurrency} at once"
    )
    lines.append("- Targets:")
    for target in roe.targets:
        lines.append(
            f"  - {target.id}: {target.base_url}, {target.environment}, "
            "synthetic data only"
        )
    return lines


def _run_section(run: RunInput) -> list[str]:
    summary = run.summary
    lines = [
        f"### {_cell(run.label)} ({run.suite})",
        "",
        "| probe | evaluated | skipped | flagged | flagged rate |",
        "| --- | ---: | ---: | ---: | ---: |",
    ]
    for probe in summary.probes:
        lines.append(
            f"| {_cell(probe.probe)} | {probe.evaluated} | {probe.skipped} | "
            f"{probe.flagged} | {_percent(probe.flagged_rate)} |"
        )
    lines.append(
        f"| all probes | {summary.evaluated} | {summary.skipped} | "
        f"{summary.flagged} | {_percent(summary.flagged_rate)} |"
    )
    hits = dict.fromkeys(summary.detectors, 0)
    for probe in summary.probes:
        for name, count in probe.failures.items():
            hits[name] = hits.get(name, 0) + count
    lines += [
        "",
        "Detector hits: "
        + ", ".join(f"{_cell(name)} {count}" for name, count in hits.items())
        + ". An attempt that both detectors flag counts once in the flagged column.",
    ]
    if summary.skipped:
        lines.append(
            f"{summary.skipped} attempts had no answer and were not evaluated."
        )
    return lines


def _fairness_section(summary: FairnessSummary) -> list[str]:
    try:
        result = evaluate(summary)
    except FairnessError as exc:
        raise ReportBuildError(f"the fairness summary cannot be judged: {exc}") from exc
    outcome = (
        "both differences are within their limits."
        if result.passed
        else "; ".join(result.reasons) + "."
    )
    lines = [
        "### Group fairness (bias)",
        "",
        f"Attribute: {summary.attribute}. Data: {summary.data}.",
        "",
        "| group | count | selection rate | true positive rate | false positive rate |",
        "| --- | ---: | ---: | ---: | ---: |",
    ]
    for group in summary.groups:
        lines.append(
            f"| {group.group} | {group.count} | {_rate(group.selection_rate)} | "
            f"{_rate(group.true_positive_rate)} | "
            f"{_rate(group.false_positive_rate)} |"
        )
    lines += [
        "",
        f"Demographic parity difference: {result.parity_difference:.4f} "
        f"(limit {DEFAULT_MAX_PARITY_DIFFERENCE:g}).",
        "",
        f"Equalized odds difference: {result.equalized_odds_difference:.4f} "
        f"(limit {DEFAULT_MAX_EQUALIZED_ODDS_DIFFERENCE:g}).",
        "",
        f"Result: {outcome}",
    ]
    return lines


def _mapping(suites: Sequence[str]) -> list[str]:
    lines = [
        "## Threat mapping",
        "",
        f"MITRE ATLAS release {ATLAS_RELEASE}, OWASP Top 10 for LLM Applications "
        f"{OWASP_LLM_EDITION}.",
        "",
    ]
    for suite in suites:
        entry = mapping_for(suite)
        lines.append(f"### {suite}")
        lines.append("")
        lines.append(
            "- STRIDE: " + ", ".join(s.replace("_", " ") for s in entry.stride)
        )
        atlas = []
        for tid in entry.atlas:
            name, tactics = ATLAS_TECHNIQUES[tid]
            atlas.append(f"{tid} {name} ({', '.join(tactics)})")
        lines.append("- ATLAS: " + ("; ".join(atlas) if atlas else "none"))
        lines.append(
            "- OWASP: " + ", ".join(f"{oid} {OWASP_LLM[oid]}" for oid in entry.owasp)
        )
        if entry.note:
            lines.append(f"- Note: {entry.note}")
        lines.append("")
    return lines[:-1]


def _overview(
    runs: Sequence[RunInput], suites: Sequence[str], fairness: FairnessSummary | None
) -> list[str]:
    lines: list[str] = []
    if runs:
        evaluated = sum(run.summary.evaluated for run in runs)
        flagged = sum(run.summary.flagged for run in runs)
        covered = ", ".join(dict.fromkeys(run.suite for run in runs))
        lines.append(
            f"{len(runs)} run(s) covering {covered}. {evaluated} attempts were "
            f"evaluated. Flagged by at least one detector: {flagged}."
        )
    if fairness is not None:
        lines.append(
            f"A group fairness summary over {len(fairness.groups)} groups is included."
        )
    lines.append(f"Suites covered: {', '.join(suites)}.")
    return lines


def build_report(
    loaded: LoadedRoE,
    runs: Sequence[RunInput],
    *,
    generated_at: datetime,
    fairness: FairnessSummary | None = None,
) -> str:
    _check(loaded, runs, fairness)
    suites = list(dict.fromkeys(run.suite for run in runs))
    if fairness is not None and FAIRNESS_SUITE not in suites:
        suites.append(FAIRNESS_SUITE)
    lines = [
        f"# Red team report: {loaded.roe.engagement_id}",
        "",
        f"Generated {generated_at.isoformat(timespec='seconds')}.",
        "",
        "## Overview",
        "",
        *_overview(runs, suites, fairness),
        "",
        *_engagement(loaded),
        "",
        "## Results",
        "",
    ]
    for run in runs:
        lines += [*_run_section(run), ""]
    if fairness is not None:
        lines += [*_fairness_section(fairness), ""]
    limitations = (
        (RUN_LIMITATIONS if runs else ())
        + COMMON_LIMITATIONS
        + (FAIRNESS_LIMITATIONS if fairness is not None else ())
    )
    lines += [*_mapping(suites), "", "## Limitations", ""]
    lines += [f"- {item}" for item in limitations]
    return "\n".join(lines) + "\n"
