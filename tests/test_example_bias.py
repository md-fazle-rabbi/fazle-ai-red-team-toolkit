"""The bias example must stay valid and work with the fairness example and report."""

from datetime import UTC, datetime
from pathlib import Path

import pytest

from redteam_toolkit.fairness import read_fairness_summary
from redteam_toolkit.report import build_report
from redteam_toolkit.roe import RoEGate, RoEViolationError, load_roe

EXAMPLES = Path(__file__).parent.parent / "examples"
EXAMPLE = EXAMPLES / "roe.stub-bias.toml"
# Inside the example's window (Oct 23 to Nov 20, 2026).
INSIDE = datetime(2026, 10, 24, 12, 0, tzinfo=UTC)


def test_the_bias_example_is_valid_and_permits_both_suites() -> None:
    gate = RoEGate(load_roe(EXAMPLE))
    for suite in ("prompt_injection", "bias"):
        target = gate.permit(
            target_id="stub-weak-local",
            suite=suite,
            url="http://127.0.0.1:8010/query",
            now=INSIDE,
        )
        assert target.id == "stub-weak-local"


def test_the_bias_example_does_not_permit_other_suites() -> None:
    gate = RoEGate(load_roe(EXAMPLE))
    with pytest.raises(RoEViolationError):
        gate.permit(
            target_id="stub-weak-local",
            suite="load",
            url="http://127.0.0.1:8010/query",
            now=INSIDE,
        )


def test_the_bias_example_works_with_the_fairness_example() -> None:
    summary = read_fairness_summary(EXAMPLES / "fairness.synthetic-example.json")
    text = build_report(load_roe(EXAMPLE), [], generated_at=INSIDE, fairness=summary)
    assert "# Red team report: stub-bias-selftest" in text
    assert "### Group fairness (bias)" in text
