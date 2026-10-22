"""Checks a Locust run against a latency and error threshold.

This reads the stats file Locust writes with --csv and sends nothing. It judges two
numbers for the whole run: the 95th percentile response time and the share of
requests that failed. A run with no requests, or too few to mean anything, cannot
pass, because an empty run would otherwise look fine.

The thresholds are inputs, not measured limits. Where they come from is the caller's
decision, and a pass only says this one run stayed inside them.
"""

from __future__ import annotations

import csv
import math
from dataclasses import dataclass
from pathlib import Path
from typing import Final

DEFAULT_MAX_P95_MS: Final = 2000.0
DEFAULT_MAX_FAILURE_RATE: Final = 0.01
# Why: a run of a handful of requests stays inside any threshold by luck. This is a
# policy floor I chose, not a measured value.
DEFAULT_MIN_REQUESTS: Final = 100
_AGGREGATE: Final = "Aggregated"


class LoadGateError(ValueError):
    """A stats file could not be read or cannot be judged."""


@dataclass(frozen=True, slots=True)
class LoadStats:
    requests: int
    failures: int
    p95_ms: float
    requests_per_second: float


@dataclass(frozen=True, slots=True)
class GateResult:
    passed: bool
    reasons: tuple[str, ...]


def _number(row: dict[str, str], column: str) -> float:
    raw = row.get(column)
    try:
        return float(raw) if raw is not None else float("nan")
    except ValueError:
        raise LoadGateError(f"column {column!r} is not a number: {raw!r}") from None


def read_locust_stats(path: Path) -> LoadStats:
    """Read the aggregated row from a Locust stats file (--csv NAME_stats.csv)."""
    with path.open(encoding="utf-8", newline="") as handle:
        rows = list(csv.DictReader(handle))
    row = next((r for r in rows if r.get("Name") == _AGGREGATE), None)
    if row is None:
        raise LoadGateError(f"no {_AGGREGATE!r} row in {path.name}")
    values = {
        column: _number(row, column)
        for column in ("Request Count", "Failure Count", "95%", "Requests/s")
    }
    missing = [name for name, value in values.items() if math.isnan(value)]
    if missing:
        raise LoadGateError(f"missing or empty columns: {', '.join(missing)}")
    return LoadStats(
        requests=int(values["Request Count"]),
        failures=int(values["Failure Count"]),
        p95_ms=values["95%"],
        requests_per_second=values["Requests/s"],
    )


def evaluate(
    stats: LoadStats,
    *,
    max_p95_ms: float = DEFAULT_MAX_P95_MS,
    max_failure_rate: float = DEFAULT_MAX_FAILURE_RATE,
    min_requests: int = DEFAULT_MIN_REQUESTS,
) -> GateResult:
    """Judge one run. Raises LoadGateError when there is too little to judge."""
    if stats.requests < min_requests:
        raise LoadGateError(
            f"the run has {stats.requests} requests, fewer than the {min_requests} "
            "needed to judge it"
        )
    reasons: list[str] = []
    if stats.p95_ms > max_p95_ms:
        reasons.append(f"p95 {stats.p95_ms:g} ms is above {max_p95_ms:g} ms")
    rate = stats.failures / stats.requests
    if rate > max_failure_rate:
        reasons.append(
            f"failure rate {rate:.2%} is above {max_failure_rate:.2%} "
            f"({stats.failures} of {stats.requests})"
        )
    return GateResult(passed=not reasons, reasons=tuple(reasons))
