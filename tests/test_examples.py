"""The example Rules of Engagement files in examples/ must stay valid.

Nothing else in the test suite loads these files, so a schema change that quietly
breaks one of them would only be caught by a person running the README's own
commands by hand. These tests catch it in CI instead.

The example files carry real dates, so every check here passes a fixed moment
inside their windows. Without that, these tests would start failing the day an
example's window ends, with no code change at all.
"""

from datetime import UTC, datetime
from pathlib import Path

import pytest

from redteam_toolkit.roe import RoEGate, RoEViolationError, load_roe

EXAMPLES = Path(__file__).parent.parent / "examples"
# Inside both examples' windows (repo1: Oct 18 to 25, stub: Oct 19 to 26, 2026).
INSIDE = datetime(2026, 10, 22, 12, 0, tzinfo=UTC)


def test_repo1_local_example_is_valid() -> None:
    loaded = load_roe(EXAMPLES / "roe.repo1-local.toml")
    assert loaded.roe.engagement_id == "repo1-local-selftest"
    target = RoEGate(loaded).permit(
        target_id="repo1-local",
        suite="prompt_injection",
        url="http://localhost:8000/query",
        now=INSIDE,
    )
    assert target.id == "repo1-local"


def test_stub_local_example_is_valid() -> None:
    loaded = load_roe(EXAMPLES / "roe.stub-local.toml")
    assert loaded.roe.engagement_id == "stub-local-selftest"
    gate = RoEGate(loaded)
    for target_id in ("stub-weak-local", "stub-hardened-local"):
        target = gate.permit(
            target_id=target_id,
            suite="prompt_injection",
            url="http://127.0.0.1:8010/query",
            now=INSIDE,
        )
        assert target.id == target_id


def test_stub_local_example_refuses_an_unlisted_suite() -> None:
    gate = RoEGate(load_roe(EXAMPLES / "roe.stub-local.toml"))
    with pytest.raises(RoEViolationError):
        gate.permit(
            target_id="stub-weak-local",
            suite="load",
            url="http://127.0.0.1:8010/query",
            now=INSIDE,
        )
