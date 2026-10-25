"""CVSS v3.1 base scores, computed from a vector string.

This module only does arithmetic. Given a base vector such as
CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N it returns the score and the severity
band that the CVSS v3.1 specification defines. It does not choose a vector for any
finding. Which vector fits a finding is a judgement, and whoever assigns one owns it.

Only the eight base metrics are accepted, in the specification's order. Temporal and
environmental metrics are refused, so a score here is always a base score.
"""

from __future__ import annotations

import math
from dataclasses import dataclass
from typing import Final

PREFIX: Final = "CVSS:3.1/"

_AV: Final = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
_AC: Final = {"L": 0.77, "H": 0.44}
_PR_UNCHANGED: Final = {"N": 0.85, "L": 0.62, "H": 0.27}
_PR_CHANGED: Final = {"N": 0.85, "L": 0.68, "H": 0.5}
_UI: Final = {"N": 0.85, "R": 0.62}
_SCOPE: Final = frozenset({"U", "C"})
_IMPACT: Final = {"H": 0.56, "L": 0.22, "N": 0.0}

_METRICS: Final[tuple[str, ...]] = ("AV", "AC", "PR", "UI", "S", "C", "I", "A")
_VALUES: Final[dict[str, frozenset[str]]] = {
    "AV": frozenset(_AV),
    "AC": frozenset(_AC),
    "PR": frozenset(_PR_UNCHANGED),
    "UI": frozenset(_UI),
    "S": _SCOPE,
    "C": frozenset(_IMPACT),
    "I": frozenset(_IMPACT),
    "A": frozenset(_IMPACT),
}
_SCALE: Final = 100_000


class CvssError(ValueError):
    """The vector is not a well formed CVSS v3.1 base vector."""


@dataclass(frozen=True, slots=True)
class CvssScore:
    vector: str
    base_score: float
    severity: str


def roundup(value: float) -> float:
    """Round up to one decimal, as the specification's Appendix A defines it.

    Why: the plain ceil(value * 10) / 10 gives wrong answers when a float sits a hair
    above a tenth. The specification works on an integer to avoid that.
    """
    scaled = round(value * _SCALE)
    if scaled % 10_000 == 0:
        return scaled / _SCALE
    return (math.floor(scaled / 10_000) + 1) / 10.0


def severity_for(score: float) -> str:
    if score == 0.0:
        return "None"
    if score <= 3.9:
        return "Low"
    if score <= 6.9:
        return "Medium"
    if score <= 8.9:
        return "High"
    return "Critical"


def parse_vector(vector: str) -> dict[str, str]:
    """Split a base vector into its metrics. Raises CvssError if it is malformed."""
    if not vector.startswith(PREFIX):
        raise CvssError(f"a vector must start with {PREFIX!r}")
    parts = vector[len(PREFIX) :].split("/")
    metrics: dict[str, str] = {}
    for part in parts:
        name, sep, value = part.partition(":")
        if not sep or name not in _VALUES:
            raise CvssError(f"{part!r} is not a base metric")
        if name in metrics:
            raise CvssError(f"the metric {name} appears twice")
        if value not in _VALUES[name]:
            raise CvssError(f"{value!r} is not a value of the metric {name}")
        metrics[name] = value
    if tuple(metrics) != _METRICS:
        raise CvssError(
            f"the base metrics must be exactly {'/'.join(_METRICS)}, in order"
        )
    return metrics


def score(vector: str) -> CvssScore:
    """Return the CVSS v3.1 base score and severity for a base vector."""
    m = parse_vector(vector)
    changed = m["S"] == "C"
    pr = (_PR_CHANGED if changed else _PR_UNCHANGED)[m["PR"]]
    iss = 1 - ((1 - _IMPACT[m["C"]]) * (1 - _IMPACT[m["I"]]) * (1 - _IMPACT[m["A"]]))
    impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15 if changed else 6.42 * iss
    exploitability = 8.22 * _AV[m["AV"]] * _AC[m["AC"]] * pr * _UI[m["UI"]]
    if impact <= 0:
        base = 0.0
    elif changed:
        base = roundup(min(1.08 * (impact + exploitability), 10.0))
    else:
        base = roundup(min(impact + exploitability, 10.0))
    return CvssScore(vector=vector, base_score=base, severity=severity_for(base))
