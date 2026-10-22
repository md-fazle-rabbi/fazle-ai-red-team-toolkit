"""A machine-readable summary of one scored run.

The summary holds counts and rates only. It never carries prompt text or answer text,
so it is safe to attach to a report. The flagged rate is the share of answered attempts
that at least one of this toolkit's detectors flagged. It is not a general bypass rate
for the target, because the detectors only look for a canary leak and personal data.
"""

from __future__ import annotations

from collections.abc import Sequence
from pathlib import Path
from typing import Final

from pydantic import BaseModel, ConfigDict, ValidationError

from redteam_toolkit.scoring import DETECTORS, ProbeScore

SCHEMA_VERSION: Final = 1
_DIGITS: Final = 4
CAVEAT: Final = (
    "Rates count only answered attempts and only the canary and personal data "
    "detectors. Each run samples its own prompts, so small differences are noise."
)


class SummaryError(ValueError):
    """A summary file could not be read."""


class ProbeSummary(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    probe: str
    evaluated: int
    skipped: int
    flagged: int
    failures: dict[str, int]
    flagged_rate: float | None


class RunSummary(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: int
    detectors: list[str]
    evaluated: int
    skipped: int
    flagged: int
    flagged_rate: float | None
    probes: list[ProbeSummary]


def _rate(flagged: int, evaluated: int) -> float | None:
    # Why: with nothing evaluated there is no rate. 0.0 would wrongly look clean.
    return round(flagged / evaluated, _DIGITS) if evaluated else None


def summarize(scores: Sequence[ProbeScore]) -> RunSummary:
    probes = [
        ProbeSummary(
            probe=score.probe,
            evaluated=score.evaluated,
            skipped=score.skipped,
            flagged=score.flagged,
            failures=dict(score.failures),
            flagged_rate=_rate(score.flagged, score.evaluated),
        )
        for score in scores
    ]
    evaluated = sum(p.evaluated for p in probes)
    flagged = sum(p.flagged for p in probes)
    return RunSummary(
        schema_version=SCHEMA_VERSION,
        detectors=list(DETECTORS),
        evaluated=evaluated,
        skipped=sum(p.skipped for p in probes),
        flagged=flagged,
        flagged_rate=_rate(flagged, evaluated),
        probes=probes,
    )


def summary_json(summary: RunSummary) -> str:
    return summary.model_dump_json(indent=2) + "\n"


def read_summary(path: Path) -> RunSummary:
    try:
        text = path.read_text(encoding="utf-8")
    except UnicodeDecodeError as exc:
        raise SummaryError(f"{path} is not text") from exc
    try:
        summary = RunSummary.model_validate_json(text)
    except ValidationError as exc:
        raise SummaryError(f"{path} is not a valid summary") from exc
    if summary.schema_version != SCHEMA_VERSION:
        raise SummaryError(
            f"{path} has schema version {summary.schema_version}, "
            f"this toolkit reads version {SCHEMA_VERSION}"
        )
    return summary


def _percent(rate: float | None) -> str:
    return "n/a" if rate is None else f"{rate * 100:.1f}%"


def _pair(before: int | None, after: int | None) -> str:
    left = "-" if before is None else str(before)
    right = "-" if after is None else str(after)
    return f"{left} > {right}"


def _count(probe: ProbeSummary | None, name: str) -> int | None:
    return None if probe is None else int(getattr(probe, name))


def format_comparison(before: RunSummary, after: RunSummary) -> str:
    """A side-by-side of two runs. A probe missing from one run shows as '-'."""
    old = {probe.probe: probe for probe in before.probes}
    new = {probe.probe: probe for probe in after.probes}
    lines = [
        f"{'probe':46} {'evaluated':>11} {'skipped':>9} {'flagged':>9} {'rate':>15}"
    ]
    for name in sorted(old.keys() | new.keys()):
        a, b = old.get(name), new.get(name)
        lines.append(
            f"{name:46} "
            f"{_pair(_count(a, 'evaluated'), _count(b, 'evaluated')):>11} "
            f"{_pair(_count(a, 'skipped'), _count(b, 'skipped')):>9} "
            f"{_pair(_count(a, 'flagged'), _count(b, 'flagged')):>9} "
            f"{_percent(a.flagged_rate if a else None)} > "
            f"{_percent(b.flagged_rate if b else None)}"
        )
    lines.append(
        f"{'all probes':46} "
        f"{_pair(before.evaluated, after.evaluated):>11} "
        f"{_pair(before.skipped, after.skipped):>9} "
        f"{_pair(before.flagged, after.flagged):>9} "
        f"{_percent(before.flagged_rate)} > {_percent(after.flagged_rate)}"
    )
    lines.append("before > after. " + CAVEAT)
    return "\n".join(lines) + "\n"
