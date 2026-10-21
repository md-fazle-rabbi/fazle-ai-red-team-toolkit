"""The garak configs for the stub must stay inside the gate and match the contract.

garak sends its own requests and does not go through send_probe. Pointed at the
target directly, nothing at run time stops it reaching a URL the Rules of
Engagement file does not allow. Pointed at the gated proxy, the proxy does. These
tests check the configs: the direct one must name a URL the stub's file allows, the
proxied one must name the proxy's own address, and both must match the contract.
"""

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest

from redteam_toolkit.cli import DEFAULT_PROXY_PORT, PROXY_HOST
from redteam_toolkit.roe import RoEGate, load_roe

ROOT = Path(__file__).parent.parent
INSIDE = datetime(2026, 10, 22, 12, 0, tzinfo=UTC)
DIRECT = "garak.stub-weak.json"
VIA_PROXY = "garak.stub-weak-via-proxy.json"


def _generator(name: str) -> dict[str, Any]:
    raw = json.loads((ROOT / "examples" / name).read_text())
    generator: dict[str, Any] = raw["rest"]["RestGenerator"]
    return generator


def _contract() -> dict[str, Any]:
    path = ROOT / "contracts" / "repo1-query-contract.json"
    contract: dict[str, Any] = json.loads(path.read_text())
    return contract


def test_the_direct_config_url_is_allowed_by_the_stub_roe_file() -> None:
    gate = RoEGate(load_roe(ROOT / "examples" / "roe.stub-local.toml"))
    target = gate.permit(
        target_id="stub-weak-local",
        suite="prompt_injection",
        url=_generator(DIRECT)["uri"],
        now=INSIDE,
    )
    assert target.id == "stub-weak-local"


def test_the_proxied_config_points_at_the_proxy_and_not_at_the_target() -> None:
    uri = _generator(VIA_PROXY)["uri"]
    assert uri == f"http://{PROXY_HOST}:{DEFAULT_PROXY_PORT}/query"
    assert uri != _generator(DIRECT)["uri"]


@pytest.mark.parametrize("name", [DIRECT, VIA_PROXY])
def test_the_request_template_puts_the_prompt_in_the_question_field(name: str) -> None:
    template = _generator(name)["req_template_json_object"]
    assert template == {"question": "$INPUT"}
    assert "question" in _contract()["request"]["fields"]


@pytest.mark.parametrize("name", [DIRECT, VIA_PROXY])
def test_the_response_field_exists_in_the_contract(name: str) -> None:
    generator = _generator(name)
    assert generator["response_json"] is True
    assert generator["response_json_field"] in _contract()["response_fields"]
