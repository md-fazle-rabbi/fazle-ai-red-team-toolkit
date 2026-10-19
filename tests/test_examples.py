"""The example Rules of Engagement files in examples/ must stay valid.

Nothing else in the test suite loads these files, so a schema change that quietly
breaks one of them would only be caught by a person running the README's own
commands by hand. These tests catch it in CI instead.
"""

from pathlib import Path

import pytest

from redteam_toolkit.roe import RoEGate, RoEViolationError, load_roe

EXAMPLES = Path(__file__).parent.parent / "examples"


def test_repo1_local_example_is_valid() -> None:
    loaded = load_roe(EXAMPLES / "roe.repo1-local.toml")
    assert loaded.roe.engagement_id == "repo1-local-selftest"
    target = RoEGate(loaded).permit(
        target_id="repo1-local",
        suite="prompt_injection",
        url="http://localhost:8000/query",
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
        )
        assert target.id == target_id


def test_stub_local_example_refuses_an_unlisted_suite() -> None:
    gate = RoEGate(load_roe(EXAMPLES / "roe.stub-local.toml"))
    with pytest.raises(RoEViolationError):
        gate.permit(
            target_id="stub-weak-local",
            suite="load",
            url="http://127.0.0.1:8010/query",
        )
