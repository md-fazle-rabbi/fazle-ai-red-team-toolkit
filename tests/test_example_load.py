"""The load example must stay valid and keep its higher self_owned limits."""

from datetime import UTC, datetime
from pathlib import Path

import pytest

from redteam_toolkit.roe import RoEGate, RoEViolationError, load_roe

EXAMPLE = Path(__file__).parent.parent / "examples" / "roe.stub-load.toml"
# Inside the example's window (Oct 22 to Nov 20, 2026).
INSIDE = datetime(2026, 10, 23, 12, 0, tzinfo=UTC)


def test_the_load_example_is_valid_and_permits_the_load_suite() -> None:
    loaded = load_roe(EXAMPLE)
    assert loaded.roe.authorization.kind == "self_owned"
    assert loaded.roe.limits.concurrency == 50
    target = RoEGate(loaded).permit(
        target_id="stub-weak-local",
        suite="load",
        url="http://127.0.0.1:8010/query",
        now=INSIDE,
    )
    assert target.id == "stub-weak-local"


def test_the_load_example_does_not_permit_other_suites() -> None:
    gate = RoEGate(load_roe(EXAMPLE))
    with pytest.raises(RoEViolationError):
        gate.permit(
            target_id="stub-weak-local",
            suite="prompt_injection",
            url="http://127.0.0.1:8010/query",
            now=INSIDE,
        )
