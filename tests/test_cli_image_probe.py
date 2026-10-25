"""The image-probe command: exit codes, counts and what it never writes.

The target is the local stub, reached in process. Nothing here opens a socket. The
probe strings are the ones already defined in test_stub_target.py and
test_stub_image.py. This module adds no attack content.
"""

import json
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from pathlib import Path

import httpx2
import pytest
from fastapi import FastAPI
from starlette.testclient import TestClient

from redteam_toolkit.cli import ENV_VAR, main
from redteam_toolkit.image_probe import MAX_TEXT_CHARS
from redteam_toolkit.roe import RoEGate, RoEViolationError, load_roe
from redteam_toolkit.stub_target import hardened_app, weak_app
from tests.roe_samples import VALID, change, with_paths, with_suites, with_window
from tests.test_stub_image import BENIGN
from tests.test_stub_target import PLAIN_INJECTION, SPACED_INJECTION

URL = "http://localhost:8000/ingest/image"
LINES = [PLAIN_INJECTION, SPACED_INJECTION, BENIGN]
IMAGE_ROE = with_paths(with_suites('["image_prompt_injection"]'), ["/ingest/image"])
EXAMPLES = Path(__file__).parent.parent / "examples"
# Why: the tests replace httpx2.Client inside the runner, so keep the real one.
REAL_CLIENT = httpx2.Client
PATCH_TARGET = "redteam_toolkit.runner.httpx2.Client"


@pytest.fixture(autouse=True)
def _clean_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv(ENV_VAR, raising=False)


def _fast_image_roe() -> str:
    return change(IMAGE_ROE, "requests_per_minute = 2", "requests_per_minute = 6000")


def _roe_file(tmp_path: Path, text: str | None = None) -> Path:
    now = datetime.now(UTC)
    live = with_window(
        _fast_image_roe() if text is None else text,
        now - timedelta(days=1),
        now + timedelta(days=1),
    )
    path = tmp_path / "roe.toml"
    path.write_text(live, encoding="utf-8")
    return path


def _probes_file(tmp_path: Path, lines: list[str] | None = None) -> Path:
    path = tmp_path / "probes.txt"
    path.write_text("\n".join(LINES if lines is None else lines), encoding="utf-8")
    return path


def _use_stub(
    monkeypatch: pytest.MonkeyPatch, factory: Callable[[], FastAPI]
) -> list[int]:
    """Make send_probe talk to the in-process stub. Returns a list of request counts."""
    app = factory()
    sent: list[int] = []

    def build(**_: object) -> httpx2.Client:
        sent.append(1)
        return TestClient(app, base_url="http://localhost:8000")

    monkeypatch.setattr(PATCH_TARGET, build)
    return sent


def _use_nothing(monkeypatch: pytest.MonkeyPatch) -> list[int]:
    """Any attempt to build an HTTP client fails the test."""
    sent: list[int] = []

    def build(**_: object) -> httpx2.Client:
        sent.append(1)
        raise AssertionError("nothing may be sent")

    monkeypatch.setattr(PATCH_TARGET, build)
    return sent


def _args(
    tmp_path: Path,
    *,
    roe: Path | None = None,
    extra: dict[str, str] | None = None,
) -> list[str]:
    extra = extra or {}
    # Why: the default probes file is only written when the test gave none, so a
    # test's own file is never overwritten.
    values = {
        "--file": str(roe or _roe_file(tmp_path)),
        "--target": "repo1-local",
        "--url": URL,
        "--probes": extra.get("--probes") or str(_probes_file(tmp_path)),
    }
    values.update(extra)
    return ["image-probe", *[part for pair in values.items() for part in pair]]


# --- a finished run ---------------------------------------------------------------


def test_weak_stub_accepts_every_image(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    _use_stub(monkeypatch, weak_app)
    out_json = tmp_path / "summary.json"
    assert main(_args(tmp_path, extra={"--json": str(out_json)})) == 0
    out = capsys.readouterr().out
    assert "image probes: sent=3 accepted=3 blocked=0 errored=0" in out
    assert "status codes: 201=3" in out
    summary = json.loads(out_json.read_text(encoding="utf-8"))
    assert summary["sent"] == 3
    assert summary["accepted"] == 3


def test_hardened_stub_blocks_the_plain_line_and_misses_the_spaced_one(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    _use_stub(monkeypatch, hardened_app)
    assert main(_args(tmp_path)) == 0
    out = capsys.readouterr().out
    assert "sent=3 accepted=2 blocked=1 errored=0" in out
    assert "status codes: 201=2 400=1" in out


def test_the_summary_file_and_the_output_hold_counts_only(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    _use_stub(monkeypatch, hardened_app)
    out_json = tmp_path / "summary.json"
    assert main(_args(tmp_path, extra={"--json": str(out_json)})) == 0
    seen = capsys.readouterr()
    text = out_json.read_text(encoding="utf-8")
    for line in LINES:
        assert line not in text
        assert line not in seen.out
        assert line not in seen.err
    assert set(json.loads(text)) == {
        "schema_version",
        "sent",
        "accepted",
        "blocked",
        "errored",
        "status_codes",
    }


def test_a_connection_failure_counts_as_errored(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    def handler(request: httpx2.Request) -> httpx2.Response:
        raise httpx2.ConnectError("refused", request=request)

    def build(**_: object) -> httpx2.Client:
        return REAL_CLIENT(transport=httpx2.MockTransport(handler))

    monkeypatch.setattr(PATCH_TARGET, build)
    assert main(_args(tmp_path)) == 0
    out = capsys.readouterr().out
    assert "sent=3 accepted=0 blocked=0 errored=3" in out
    assert "status codes: no_response=3" in out


# --- refusals: exit 2, nothing sent -----------------------------------------------


def test_no_rules_file_means_no_run(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    sent = _use_nothing(monkeypatch)
    args = [
        "image-probe",
        "--target",
        "repo1-local",
        "--url",
        URL,
        "--probes",
        str(_probes_file(tmp_path)),
    ]
    assert main(args) == 2
    assert "No file, no run" in capsys.readouterr().err
    assert sent == []


def test_a_file_that_does_not_allow_the_suite_refuses(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    sent = _use_nothing(monkeypatch)
    text = change(
        with_paths(VALID, ["/ingest/image"]),
        "requests_per_minute = 2",
        "requests_per_minute = 6000",
    )
    roe = _roe_file(tmp_path, text)
    assert main(_args(tmp_path, roe=roe)) == 2
    assert "not authorized" in capsys.readouterr().err
    assert sent == []


def test_a_path_outside_the_scope_refuses(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    sent = _use_nothing(monkeypatch)
    args = _args(tmp_path, extra={"--url": "http://localhost:8000/admin"})
    assert main(args) == 2
    assert sent == []


def test_a_wrong_target_refuses(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    sent = _use_nothing(monkeypatch)
    assert main(_args(tmp_path, extra={"--target": "other"})) == 2
    assert sent == []


def test_a_refusal_comes_before_the_probes_file_is_read(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _use_nothing(monkeypatch)
    args = _args(
        tmp_path, extra={"--target": "other", "--probes": str(tmp_path / "no")}
    )
    assert main(args) == 2


def test_using_up_the_request_total_stops_the_run_and_writes_no_summary(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    _use_stub(monkeypatch, weak_app)
    text = change(_fast_image_roe(), "total_requests = 500", "total_requests = 1")
    out_json = tmp_path / "summary.json"
    args = _args(
        tmp_path, roe=_roe_file(tmp_path, text), extra={"--json": str(out_json)}
    )
    assert main(args) == 2
    err = capsys.readouterr().err
    assert "the run stopped and wrote no summary" in err
    assert not out_json.exists()


# --- input that cannot be used: exit 3, nothing sent ------------------------------


def test_an_empty_probes_file_exits_3(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    sent = _use_nothing(monkeypatch)
    probes = tmp_path / "empty.txt"
    probes.write_text("\n  \n", encoding="utf-8")
    assert main(_args(tmp_path, extra={"--probes": str(probes)})) == 3
    assert "has no probe lines" in capsys.readouterr().err
    assert sent == []


def test_a_missing_probes_file_exits_3(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    sent = _use_nothing(monkeypatch)
    assert main(_args(tmp_path, extra={"--probes": str(tmp_path / "none.txt")})) == 3
    assert sent == []


def test_a_line_that_is_too_long_exits_3_and_is_not_quoted(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    sent = _use_nothing(monkeypatch)
    long_line = "x" * (MAX_TEXT_CHARS + 1)
    probes = _probes_file(tmp_path, [BENIGN, long_line])
    assert main(_args(tmp_path, extra={"--probes": str(probes)})) == 3
    err = capsys.readouterr().err
    assert "line 2 is over" in err
    assert long_line not in err
    assert sent == []


def test_a_summary_that_cannot_be_written_exits_3(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    _use_stub(monkeypatch, weak_app)
    args = _args(tmp_path, extra={"--json": str(tmp_path / "no-such-dir" / "out.json")})
    assert main(args) == 3
    assert "cannot write summary" in capsys.readouterr().err


# --- the parser and the example file ----------------------------------------------


@pytest.mark.parametrize("missing", ["--target", "--url", "--probes"])
def test_the_parser_requires_target_url_and_probes(
    tmp_path: Path, missing: str
) -> None:
    args = _args(tmp_path)
    index = args.index(missing)
    del args[index : index + 2]
    with pytest.raises(SystemExit) as excinfo:
        main(args)
    assert excinfo.value.code == 2


def test_the_stub_image_example_allows_only_the_upload_path() -> None:
    gate = RoEGate(load_roe(EXAMPLES / "roe.stub-image.toml"))
    inside = datetime(2026, 11, 1, 12, 0, tzinfo=UTC)
    for target_id in ("stub-weak-local", "stub-hardened-local"):
        target = gate.permit(
            target_id=target_id,
            suite="image_prompt_injection",
            url="http://127.0.0.1:8010/ingest/image",
            now=inside,
        )
        assert target.id == target_id
    for suite, path in (
        ("prompt_injection", "ingest/image"),
        ("image_prompt_injection", "query"),
    ):
        with pytest.raises(RoEViolationError):
            gate.permit(
                target_id="stub-weak-local",
                suite=suite,
                url=f"http://127.0.0.1:8010/{path}",
                now=inside,
            )
