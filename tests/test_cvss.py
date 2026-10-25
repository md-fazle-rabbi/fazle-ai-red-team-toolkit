"""The CVSS v3.1 base score arithmetic.

The expected scores below are the widely published values for these vectors, for
example the 9.8 for a network, no privileges, no interaction, high impact flaw. They
are not computed by the code under test.
"""

import dataclasses

import pytest

from redteam_toolkit.cvss import (
    CvssError,
    parse_vector,
    roundup,
    score,
    severity_for,
)

P = "CVSS:3.1/"


@pytest.mark.parametrize(
    ("vector", "expected", "band"),
    [
        (P + "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8, "Critical"),
        (P + "AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", 10.0, "Critical"),
        (P + "AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", 6.1, "Medium"),
        (P + "AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H", 7.8, "High"),
        (P + "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", 7.5, "High"),
        (P + "AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H", 7.5, "High"),
        (P + "AV:N/AC:L/PR:L/UI:N/S:C/C:L/I:L/A:N", 6.4, "Medium"),
        (P + "AV:P/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N", 1.6, "Low"),
    ],
)
def test_published_scores(vector: str, expected: float, band: str) -> None:
    result = score(vector)
    assert result.base_score == expected
    assert result.severity == band
    assert result.vector == vector


@pytest.mark.parametrize("scope", ["U", "C"])
def test_no_impact_scores_zero_and_none(scope: str) -> None:
    result = score(P + f"AV:N/AC:L/PR:N/UI:N/S:{scope}/C:N/I:N/A:N")
    assert result.base_score == 0.0
    assert result.severity == "None"


def test_changed_scope_raises_the_needed_privilege_weight() -> None:
    unchanged = score(P + "AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N")
    changed = score(P + "AV:N/AC:L/PR:L/UI:N/S:C/C:L/I:L/A:N")
    assert changed.base_score > unchanged.base_score


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        (4.0, 4.0),
        (4.02, 4.1),
        (4.00002, 4.1),
        (4.000001, 4.0),
        (0.0, 0.0),
        (9.99, 10.0),
    ],
)
def test_roundup_follows_the_specification(value: float, expected: float) -> None:
    assert roundup(value) == expected


@pytest.mark.parametrize(
    ("value", "band"),
    [
        (0.0, "None"),
        (0.1, "Low"),
        (3.9, "Low"),
        (4.0, "Medium"),
        (6.9, "Medium"),
        (7.0, "High"),
        (8.9, "High"),
        (9.0, "Critical"),
        (10.0, "Critical"),
    ],
)
def test_severity_bands(value: float, band: str) -> None:
    assert severity_for(value) == band


def test_parse_vector_returns_the_metrics_in_order() -> None:
    metrics = parse_vector(P + "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N")
    assert list(metrics) == ["AV", "AC", "PR", "UI", "S", "C", "I", "A"]
    assert metrics["C"] == "H"


@pytest.mark.parametrize(
    ("vector", "message"),
    [
        ("AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", "must start with"),
        ("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", "must start with"),
        (P, "not a base metric"),
        (P + "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A", "not a base metric"),
        (P + "XX:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", "not a base metric"),
        (P + "AV:N/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", "appears twice"),
        (P + "AV:Z/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", "not a value"),
        (P + "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N", "exactly"),
        (P + "AC:L/AV:N/PR:N/UI:N/S:U/C:H/I:N/A:N", "in order"),
        (P + "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N/E:H", "not a base metric"),
    ],
)
def test_malformed_vectors_are_refused(vector: str, message: str) -> None:
    with pytest.raises(CvssError, match=message):
        score(vector)


def test_the_score_is_frozen() -> None:
    result = score(P + "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N")
    with pytest.raises(dataclasses.FrozenInstanceError):
        result.base_score = 0.0  # type: ignore[misc]
