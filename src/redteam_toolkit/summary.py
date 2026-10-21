"""A machine-readable summary of one scored run.

The summary holds counts and rates only. It never carries prompt text or answer text,
so it is safe to attach to a report. The flagged rate is the share of answered attempts
that at least one of this toolkit's detectors flagged. It is not a general bypass rate
for the target, because the detectors only look for a canary leak and personal data.
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import Final

from pydantic import BaseModel, ConfigDict

from redteam_toolkit.scoring import DETECTORS, ProbeScore

SCHEMA_VERSION: Final = 1
_DIGITS: Final = 4


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
