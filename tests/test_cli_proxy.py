"""Tests for the proxy command. uvicorn.run is replaced, so no socket is opened."""

from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
import uvicorn
from fastapi import FastAPI
from starlette.testclient import TestClient

from redteam_toolkit.cli import DEFAULT_PROXY_PORT, ENV_VAR, PROXY_HOST, main
from tests.roe_samples import VALID, with_window


class _Served:
    def __init__(self) -> None:
        self.app: FastAPI | None = None
        self.host = ""
        self.port = 0
        self.calls = 0


@pytest.fixture
def served(monkeypatch: pytest.MonkeyPatch) -> _Served:
    record = _Served()

    def fake_run(app: FastAPI, **kwargs: Any) -> None:
        record.calls += 1
        record.app = app
        record.host = kwargs["host"]
        record.port = kwargs["port"]

    monkeypatch.setattr(uvicorn, "run", fake_run)
    monkeypatch.delenv(ENV_VAR, raising=False)
    return record


def _live_file(tmp_path: Path) -> Path:
    now = datetime.now(UTC)
    text = with_window(VALID, now - timedelta(days=1), now + timedelta(days=1))
    path = tmp_path / "roe.toml"
    path.write_text(text, encoding="utf-8")
    return path


def _args(roe: Path, *extra: str, suite: str = "prompt_injection") -> list[str]:
    return [
        "proxy",
        "--file",
        str(roe),
        "--target",
        "repo1-local",
        "--suite",
        suite,
        *extra,
    ]


def test_an_authorized_proxy_starts_on_localhost_with_the_default_port(
    tmp_path: Path, served: _Served, capsys: pytest.CaptureFixture[str]
) -> None:
    roe = _live_file(tmp_path)
    audit = tmp_path / "audit.jsonl"
    assert main(_args(roe, "--audit", str(audit))) == 0
    assert served.calls == 1
    assert served.host == PROXY_HOST == "127.0.0.1"
    assert served.port == DEFAULT_PROXY_PORT
    line = capsys.readouterr().out
    assert "upstream=http://localhost:8000" in line
    assert "suite=prompt_injection" in line
    assert f"audit={audit}" in line


def test_the_port_can_be_chosen(tmp_path: Path, served: _Served) -> None:
    assert main(_args(_live_file(tmp_path), "--port", "9100")) == 0
    assert served.port == 9100


@pytest.mark.parametrize("port", ["80", "70000", "abc"])
def test_a_bad_port_is_rejected(tmp_path: Path, served: _Served, port: str) -> None:
    with pytest.raises(SystemExit):
        main(_args(_live_file(tmp_path), "--port", port))
    assert served.calls == 0


def test_a_wrong_target_never_starts_the_proxy(
    tmp_path: Path, served: _Served, capsys: pytest.CaptureFixture[str]
) -> None:
    argv = _args(_live_file(tmp_path))
    argv[argv.index("repo1-local")] = "no-such-target"
    assert main(argv) == 2
    assert served.calls == 0
    assert "refused" in capsys.readouterr().err


def test_a_suite_outside_the_file_never_starts_the_proxy(
    tmp_path: Path, served: _Served
) -> None:
    assert main(_args(_live_file(tmp_path), suite="bias")) == 2
    assert served.calls == 0


def test_the_default_audit_file_is_made_under_runs(
    tmp_path: Path, served: _Served, monkeypatch: pytest.MonkeyPatch
) -> None:
    roe = _live_file(tmp_path)
    monkeypatch.chdir(tmp_path)
    assert main(_args(roe)) == 0
    assert (tmp_path / "runs").is_dir()


def test_the_started_proxy_refuses_a_path_outside_the_file_and_audits_it(
    tmp_path: Path, served: _Served
) -> None:
    audit = tmp_path / "audit.jsonl"
    assert main(_args(_live_file(tmp_path), "--audit", str(audit))) == 0
    assert served.app is not None
    response = TestClient(served.app).post("/admin", json={"question": "hi"})
    assert response.status_code == 403
    lines = audit.read_text().splitlines()
    assert len(lines) == 1
    assert '"outcome": "refused"' in lines[0]
