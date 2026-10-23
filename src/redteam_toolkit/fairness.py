"""Checks a group fairness summary against thresholds.

The summary is written by a separate script that runs in its own environment, so this
module needs no data science packages. It holds per group counts and rates only, and
the data must be marked synthetic. The two differences are worked out here from the
group rates and are never read from the file, so a file cannot claim a gap that its own
rates do not show.

A summary with one group, a group too small to mean anything, or no group rates to
compare cannot pass, because nothing was actually compared. The thresholds are inputs,
not measured limits, and a pass only says this one summary stayed inside them.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Annotated, Final, Literal

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    StringConstraints,
    ValidationError,
    model_validator,
)

SCHEMA_VERSION: Final = 1
# Why: these are policy values I chose, not measured ones.
DEFAULT_MAX_PARITY_DIFFERENCE: Final = 0.10
DEFAULT_MAX_EQUALIZED_ODDS_DIFFERENCE: Final = 0.10
DEFAULT_MIN_GROUP_SIZE: Final = 30
_DIGITS: Final = 6

Rate = Annotated[float, Field(ge=0, le=1)]
Name = Annotated[
    str,
    StringConstraints(
        strip_whitespace=True,
        min_length=1,
        max_length=40,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9 ._-]*$",
    ),
]


class FairnessError(ValueError):
    """A summary could not be read or cannot be judged."""


class GroupRates(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    group: Name
    count: Annotated[int, Field(ge=1)]
    selection_rate: Rate
    true_positive_rate: Rate | None = None
    false_positive_rate: Rate | None = None


class FairnessSummary(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: int
    attribute: Name
    # Why: the only accepted value. A summary of real personal data is out of scope.
    data: Literal["synthetic"]
    groups: list[GroupRates]

    @model_validator(mode="after")
    def check_unique_groups(self) -> FairnessSummary:
        names = [g.group for g in self.groups]
        if len(names) != len(set(names)):
            raise ValueError("duplicate group name")
        return self


@dataclass(frozen=True, slots=True)
class FairnessResult:
    passed: bool
    reasons: tuple[str, ...]
    parity_difference: float
    equalized_odds_difference: float


def read_fairness_summary(path: Path) -> FairnessSummary:
    try:
        text = path.read_text(encoding="utf-8")
    except UnicodeDecodeError as exc:
        raise FairnessError(f"{path} is not text") from exc
    try:
        summary = FairnessSummary.model_validate_json(text)
    except ValidationError as exc:
        raise FairnessError(f"{path} is not a valid fairness summary") from exc
    if summary.schema_version != SCHEMA_VERSION:
        raise FairnessError(
            f"{path} has schema version {summary.schema_version}, "
            f"this toolkit reads version {SCHEMA_VERSION}"
        )
    return summary


def _spread(values: Sequence[float]) -> float:
    # Why: rounding keeps 0.6 minus 0.5 from landing a hair above a limit of 0.1.
    return round(max(values) - min(values), _DIGITS)


def evaluate(
    summary: FairnessSummary,
    *,
    max_parity_difference: float = DEFAULT_MAX_PARITY_DIFFERENCE,
    max_equalized_odds_difference: float = DEFAULT_MAX_EQUALIZED_ODDS_DIFFERENCE,
    min_group_size: int = DEFAULT_MIN_GROUP_SIZE,
) -> FairnessResult:
    """Judge one summary. Raises FairnessError when there is too little to judge."""
    groups = summary.groups
    if len(groups) < 2:
        raise FairnessError("a fairness check needs at least two groups")
    small = [g.group for g in groups if g.count < min_group_size]
    if small:
        raise FairnessError(
            f"groups with fewer than {min_group_size} rows cannot be judged: "
            + ", ".join(small)
        )
    tprs = [g.true_positive_rate for g in groups if g.true_positive_rate is not None]
    fprs = [g.false_positive_rate for g in groups if g.false_positive_rate is not None]
    if len(tprs) < 2 or len(fprs) < 2:
        raise FairnessError(
            "at least two groups need a true positive rate and a false positive rate"
        )
    parity = _spread([g.selection_rate for g in groups])
    odds = max(_spread(tprs), _spread(fprs))
    reasons: list[str] = []
    if parity > max_parity_difference:
        reasons.append(
            f"demographic parity difference {parity:.4f} is above "
            f"{max_parity_difference:g}"
        )
    if odds > max_equalized_odds_difference:
        reasons.append(
            f"equalized odds difference {odds:.4f} is above "
            f"{max_equalized_odds_difference:g}"
        )
    return FairnessResult(
        passed=not reasons,
        reasons=tuple(reasons),
        parity_difference=parity,
        equalized_odds_difference=odds,
    )


def _rate_text(rate: float | None) -> str:
    return "n/a" if rate is None else f"{rate:.4f}"


def format_groups(summary: FairnessSummary) -> str:
    lines = [f"attribute={summary.attribute} data={summary.data}"]
    lines += [
        f"group={g.group} count={g.count} "
        f"selection_rate={_rate_text(g.selection_rate)} "
        f"true_positive_rate={_rate_text(g.true_positive_rate)} "
        f"false_positive_rate={_rate_text(g.false_positive_rate)}"
        for g in summary.groups
    ]
    return "\n".join(lines) + "\n"
