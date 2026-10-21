"""The garak config for the stub must stay inside the gate and match the contract.

garak sends its own requests and does not go through send_probe, so nothing at
run time stops it reaching a URL the Rules of Engagement file does not allow.
This test is the check that exists: the config's URL must be allowed by the
stub's Rules of Engagement file, and its field names must match the contract.
"""

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from redteam_toolkit.roe import RoEGate, load_roe

ROOT = Path(__file__).parent.parent
INSIDE = datetime(2026, 10, 22, 12, 0, tzinfo=UTC)


def _generator() -> dict[str, Any]:
    raw = json.loads((ROOT / "examples" / "garak.stub-weak.json").read_text())
    generator: dict[str, Any] = raw["rest"]["RestGenerator"]
    return generator


def _contract() -> dict[str, Any]:
    path = ROOT / "contracts" / "repo1-query-contract.json"
    contract: dict[str, Any] = json.loads(path.read_text())
    return contract


def test_the_config_url_is_allowed_by_the_stub_rules_of_engagement_file() -> None:
    gate = RoEGate(load_roe(ROOT / "examples" / "roe.stub-local.toml"))
    target = gate.permit(
        target_id="stub-weak-local",
        suite="prompt_injection",
        url=_generator()["uri"],
        now=INSIDE,
    )
    assert target.id == "stub-weak-local"


def test_the_request_template_puts_the_prompt_in_the_question_field() -> None:
    template = _generator()["req_template_json_object"]
    assert template == {"question": "$INPUT"}
    assert "question" in _contract()["request"]["fields"]


def test_the_response_field_exists_in_the_contract() -> None:
    generator = _generator()
    assert generator["response_json"] is True
    assert generator["response_json_field"] in _contract()["response_fields"]
