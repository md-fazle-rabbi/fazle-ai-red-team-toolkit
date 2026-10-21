"""Tests for the gated proxy. The upstream is always our own stub or a mock."""

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import httpx2
import pytest
from starlette.testclient import TestClient

from redteam_toolkit.limits import RequestBudget
from redteam_toolkit.proxy import AuditEntry, JsonlAudit, create_proxy_app
from redteam_toolkit.roe import Limits, RoEGate, load_roe
from redteam_toolkit.stub_target import weak_app
from tests.roe_samples import VALID, with_window

UPSTREAM = "http://localhost:8000"
QUESTION = {"question": "Who is the support contact?"}


def _gate(tmp_path: Path) -> RoEGate:
    now = datetime.now(UTC)
    text = with_window(VALID, now - timedelta(days=1), now + timedelta(days=1))
    path = tmp_path / "roe.toml"
    path.write_text(text)
    return RoEGate(load_roe(path))


def _stub_client() -> httpx2.Client:
    return TestClient(weak_app(), base_url=UPSTREAM)


def _forbidden_client() -> httpx2.Client:
    def boom(request: httpx2.Request) -> httpx2.Response:
        raise AssertionError("the proxy must not reach the upstream when refusing")

    return httpx2.Client(transport=httpx2.MockTransport(boom))


def _proxy(
    tmp_path: Path,
    *,
    suite: str = "prompt_injection",
    client: httpx2.Client | None = None,
    budget: RequestBudget | None = None,
    entries: list[AuditEntry] | None = None,
) -> TestClient:
    sink = entries.append if entries is not None else None
    app = create_proxy_app(
        _gate(tmp_path),
        target_id="repo1-local",
        suite=suite,
        upstream_base=UPSTREAM,
        budget=budget,
        client=client if client is not None else _stub_client(),
        audit=sink,
    )
    return TestClient(app)


def test_a_permitted_request_is_forwarded_to_the_target(tmp_path: Path) -> None:
    response = _proxy(tmp_path).post("/query", json=QUESTION)
    assert response.status_code == 200
    assert "answer" in response.json()


def test_a_path_the_file_does_not_allow_is_refused_and_never_sent(
    tmp_path: Path,
) -> None:
    proxy = _proxy(tmp_path, client=_forbidden_client())
    response = proxy.post("/admin", json=QUESTION)
    assert response.status_code == 403
    assert "refused" in response.json()


def test_a_suite_the_file_does_not_allow_is_refused(tmp_path: Path) -> None:
    proxy = _proxy(tmp_path, suite="bias", client=_forbidden_client())
    assert proxy.post("/query", json=QUESTION).status_code == 403


def test_a_spent_budget_is_refused(tmp_path: Path) -> None:
    limits = Limits(requests_per_minute=60, total_requests=1, concurrency=1)
    budget = RequestBudget(limits, clock=lambda: 1000.0, sleep=lambda _s: None)
    proxy = _proxy(tmp_path, budget=budget)
    assert proxy.post("/query", json=QUESTION).status_code == 200
    assert proxy.post("/query", json=QUESTION).status_code == 403


def test_an_unreachable_target_gives_a_502(tmp_path: Path) -> None:
    def refuse(request: httpx2.Request) -> httpx2.Response:
        raise httpx2.ConnectError("refused", request=request)

    client = httpx2.Client(transport=httpx2.MockTransport(refuse))
    response = _proxy(tmp_path, client=client).post("/query", json=QUESTION)
    assert response.status_code == 502
    assert "ConnectError" in response.json()["error"]


def test_the_targets_status_code_is_passed_through(tmp_path: Path) -> None:
    def blocked(request: httpx2.Request) -> httpx2.Response:
        return httpx2.Response(400, json={"detail": "blocked"})

    client = httpx2.Client(transport=httpx2.MockTransport(blocked))
    response = _proxy(tmp_path, client=client).post("/query", json=QUESTION)
    assert response.status_code == 400
    assert response.json() == {"detail": "blocked"}


def test_a_body_that_is_not_a_json_object_is_rejected(tmp_path: Path) -> None:
    response = _proxy(tmp_path, client=_forbidden_client()).post(
        "/query", json=["not", "an", "object"]
    )
    assert response.status_code == 422


def test_every_outcome_is_audited_without_bodies(tmp_path: Path) -> None:
    entries: list[AuditEntry] = []
    proxy = _proxy(tmp_path, entries=entries)
    proxy.post("/query", json=QUESTION)
    proxy.post("/admin", json=QUESTION)
    assert [e.outcome for e in entries] == ["forwarded", "refused"]
    assert entries[0].status_code == 200
    assert entries[1].status_code == 403
    for entry in entries:
        assert "support contact" not in str(entry)


def test_an_upstream_failure_is_audited(tmp_path: Path) -> None:
    def refuse(request: httpx2.Request) -> httpx2.Response:
        raise httpx2.ConnectError("refused", request=request)

    entries: list[AuditEntry] = []
    client = httpx2.Client(transport=httpx2.MockTransport(refuse))
    _proxy(tmp_path, client=client, entries=entries).post("/query", json=QUESTION)
    assert [e.outcome for e in entries] == ["upstream_error"]


def test_the_jsonl_audit_writes_one_line_per_entry(tmp_path: Path) -> None:
    log = tmp_path / "audit.jsonl"
    sink = JsonlAudit(log)
    entry = AuditEntry(
        "t", "repo1-local", "prompt_injection", "query", "forwarded", 200, ""
    )
    sink(entry)
    sink(entry)
    lines = log.read_text().splitlines()
    assert len(lines) == 2
    assert json.loads(lines[0])["outcome"] == "forwarded"


def test_each_proxy_is_fixed_to_one_suite(tmp_path: Path) -> None:
    entries: list[AuditEntry] = []
    proxy = _proxy(tmp_path, suite="pii_leakage", entries=entries)
    proxy.post("/query", json={**QUESTION, "suite": "bias"})
    assert entries[0].suite == "pii_leakage"


@pytest.mark.parametrize("path", ["query", "query/stream"])
def test_the_allowed_paths_from_the_file_are_forwarded(
    tmp_path: Path, path: str
) -> None:
    entries: list[AuditEntry] = []
    _proxy(tmp_path, entries=entries).post(f"/{path}", json=QUESTION)
    assert entries[0].outcome == "forwarded"
