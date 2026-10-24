"""Checks a robustness summary against an accuracy drop threshold.

A separate script in its own environment (IBM ART is too heavy for this package)
trains a small classifier on synthetic data and measures its accuracy while the input
numbers are perturbed by a bounded amount, one epsilon at a time. It writes a summary
of rates only. This module reads that file and sends nothing.

The gate compares the clean accuracy with the accuracy at one chosen epsilon. A summary
with too few rows, or without a measurement at that epsilon, cannot be judged, because
nothing was actually compared. The threshold is an input, not a measured limit, and a
pass only says this one model on this one synthetic data set stayed inside it.
"""

from __future__ import annotations

import itertools
import math
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
DEFAULT_EPSILON: Final = 0.1
DEFAULT_MAX_ACCURACY_DROP: Final = 0.10
DEFAULT_MIN_ROWS: Final = 100
_DIGITS: Final = 6
_EPSILON_TOLERANCE: Final = 1e-9

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


class RobustnessError(ValueError):
    """A summary could not be read or cannot be judged."""


class Point(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    epsilon: Annotated[float, Field(gt=0)]
    accuracy: Rate


class RobustnessSummary(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: int
    # Why: the only accepted value. A summary built from real data is out of scope.
    data: Literal["synthetic"]
    model: Name
    attack: Name
    rows: Annotated[int, Field(ge=1)]
    clean_accuracy: Rate
    points: Annotated[list[Point], Field(min_length=1)]

    @model_validator(mode="after")
    def check_epsilons_increase(self) -> RobustnessSummary:
        epsilons = [p.epsilon for p in self.points]
        if any(b <= a for a, b in itertools.pairwise(epsilons)):
            raise ValueError("epsilons must be strictly increasing")
        return self


@dataclass(frozen=True, slots=True)
class RobustnessResult:
    passed: bool
    reasons: tuple[str, ...]
    epsilon: float
    clean_accuracy: float
    accuracy: float
    accuracy_drop: float


def read_robustness_summary(path: Path) -> RobustnessSummary:
    try:
        text = path.read_text(encoding="utf-8")
    except UnicodeDecodeError as exc:
        raise RobustnessError(f"{path} is not text") from exc
    try:
        summary = RobustnessSummary.model_validate_json(text)
    except ValidationError as exc:
        raise RobustnessError(f"{path} is not a valid robustness summary") from exc
    if summary.schema_version != SCHEMA_VERSION:
        raise RobustnessError(
            f"{path} has schema version {summary.schema_version}, "
            f"this toolkit reads version {SCHEMA_VERSION}"
        )
    return summary


def evaluate_robustness(
    summary: RobustnessSummary,
    *,
    epsilon: float = DEFAULT_EPSILON,
    max_accuracy_drop: float = DEFAULT_MAX_ACCURACY_DROP,
    min_rows: int = DEFAULT_MIN_ROWS,
) -> RobustnessResult:
    """Judge one summary. Raises RobustnessError when there is too little to judge."""
    if summary.rows < min_rows:
        raise RobustnessError(
            f"the summary has {summary.rows} rows, fewer than the {min_rows} "
            "needed to judge it"
        )
    point = next(
        (
            p
            for p in summary.points
            if math.isclose(p.epsilon, epsilon, abs_tol=_EPSILON_TOLERANCE)
        ),
        None,
    )
    if point is None:
        measured = ", ".join(f"{p.epsilon:g}" for p in summary.points)
        raise RobustnessError(
            f"no measurement at epsilon {epsilon:g} (measured: {measured})"
        )
    # Why: rounding keeps 0.9 minus 0.8 from landing a hair above a limit of 0.1.
    drop = round(summary.clean_accuracy - point.accuracy, _DIGITS)
    reasons: list[str] = []
    if drop > max_accuracy_drop:
        reasons.append(
            f"accuracy drop {drop:.4f} at epsilon {epsilon:g} is above "
            f"{max_accuracy_drop:g}"
        )
    return RobustnessResult(
        passed=not reasons,
        reasons=tuple(reasons),
        epsilon=epsilon,
        clean_accuracy=summary.clean_accuracy,
        accuracy=point.accuracy,
        accuracy_drop=drop,
    )


def format_points(summary: RobustnessSummary) -> str:
    lines = [
        f"model={summary.model} attack={summary.attack} data={summary.data} "
        f"rows={summary.rows} clean_accuracy={summary.clean_accuracy:.4f}"
    ]
    lines += [
        f"epsilon={p.epsilon:g} accuracy={p.accuracy:.4f}" for p in summary.points
    ]
    return "\n".join(lines) + "\n"
