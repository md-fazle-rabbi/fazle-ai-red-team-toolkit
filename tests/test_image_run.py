"""The image probe run: reading lines, sending through the gate, counting outcomes.

The target is the local stub, reached in process through Starlette's TestClient, or a
mock transport. Nothing here opens a socket. The probe strings are the ones already
defined in test_stub_target.py and test_stub_image.py. This module adds no attack
content.
"""

import json
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import httpx2
import pytest
from fastapi import FastAPI
from pydantic import ValidationError
from starlette.testclient import TestClient

from redteam_toolkit.image_probe import MAX_TEXT_CHARS
from redteam_toolkit.image_run import (
    NO_RESPONSE,
    SUITE,
    ImageRunError,
    ImageRunSummary,
    classify,
    image_run_json,
    read_probe_lines,
    run_image_probes,
)
from redteam_toolkit.limits import BudgetExhaustedError, RequestBudget
from redteam_toolkit.roe import Limits, RoEGate, RoEViolationError, load_roe
from redteam_toolkit.runner import ProbeResult
from redteam_toolkit.stub_target import hardened_app, weak_app
from tests.roe_samples import VALID, with_paths, with_suites, with_window
from tests.test_stub_image import BENIGN
from tests.test_stub_target import PLAIN_INJECTION, SPACED_INJECTION

URL = "http://localhost:8000/ingest/image"
IMAGE_ROE = with_paths(with_suites('["image_prompt_injection"]'), ["/ingest/image"])
LINES = [PLAIN_INJECTION, SPACED_INJECTION, BENIGN]


def _gate(tmp_path: Path, roe_text: str = IMAGE_ROE) -> RoEGate:
    path = tmp_path / "roe.toml"
    now = datetime.now(UTC)
    live = with_window(roe_text, now - timedelta(days=1), now + timedelta(days=1))
    path.write_text(live, encoding="utf-8")
    return RoEGate(load_roe(path))


def _stub(app_factory: Callable[[], FastAPI]) -> httpx2.Client:
    return TestClient(app_factory(), base_url="http://localhost:8000")


def _answering(status: int, seen: list[httpx2.Request] | None = None) -> httpx2.Client:
    def handler(request: httpx2.Request) -> httpx2.Response:
        if seen is not None:
            seen.append(request)
        return httpx2.Response(status, json={})

    return httpx2.Client(transport=httpx2.MockTransport(handler))


def _unreachable() -> httpx2.Client:
    def handler(request: httpx2.Request) -> httpx2.Response:
        raise httpx2.ConnectError("refused", request=request)

    return httpx2.Client(transport=httpx2.MockTransport(handler))


def _forbidden() -> httpx2.Client:
    def handler(request: httpx2.Request) -> httpx2.Response:
        raise AssertionError("nothing may be sent")

    return httpx2.Client(transport=httpx2.MockTransport(handler))


def _budget(total: int) -> RequestBudget:
    # Why: a clock that never moves and a sleep that does nothing, so no test waits.
    limits = Limits(requests_per_minute=60, total_requests=total, concurrency=1)
    return RequestBudget(limits, clock=lambda: 1000.0, sleep=lambda _seconds: None)


def _result(status: int | None, error: str | None = None) -> ProbeResult:
    return ProbeResult(
        target_id="repo1-local",
        suite=SUITE,
        url=URL,
        status_code=status,
        body="",
        elapsed_seconds=0.0,
        error=error,
    )


def _run(
    tmp_path: Path,
    client: httpx2.Client,
    lines: list[str] | None = None,
    **extra: Any,
) -> ImageRunSummary:
    return run_image_probes(
        _gate(tmp_path),
        target_id="repo1-local",
        url=URL,
        lines=LINES if lines is None else lines,
        client=client,
        **extra,
    )


# --- reading the probes file -----------------------------------------------------


def test_blank_lines_and_spacing_are_dropped_and_order_is_kept(tmp_path: Path) -> None:
    path = tmp_path / "probes.txt"
    path.write_text(
        f"{PLAIN_INJECTION}\r\n\n   \n  {SPACED_INJECTION}  \n{BENIGN}",
        encoding="utf-8",
    )
    assert read_probe_lines(path) == LINES


def test_a_byte_order_mark_is_not_part_of_the_first_line(tmp_path: Path) -> None:
    path = tmp_path / "probes.txt"
    path.write_bytes(b"\xef\xbb\xbf" + BENIGN.encode("utf-8"))
    assert read_probe_lines(path) == [BENIGN]


def test_a_form_feed_inside_a_line_does_not_split_it(tmp_path: Path) -> None:
    path = tmp_path / "probes.txt"
    path.write_text(f"{BENIGN}\x0c{BENIGN}\n", encoding="utf-8")
    assert read_probe_lines(path) == [f"{BENIGN}\x0c{BENIGN}"]


@pytest.mark.parametrize("content", ["", "\n\n", "  \r\n \t \n"])
def test_a_file_with_no_lines_is_refused(tmp_path: Path, content: str) -> None:
    path = tmp_path / "probes.txt"
    path.write_text(content, encoding="utf-8")
    with pytest.raises(ImageRunError, match="no probe lines"):
        read_probe_lines(path)


def test_a_missing_file_is_refused(tmp_path: Path) -> None:
    with pytest.raises(ImageRunError, match="cannot read"):
        read_probe_lines(tmp_path / "nope.txt")


def test_a_file_that_is_not_utf8_is_refused(tmp_path: Path) -> None:
    path = tmp_path / "probes.txt"
    path.write_bytes(b"\xff\xfe\x00 not text")
    with pytest.raises(ImageRunError, match="not UTF-8 text"):
        read_probe_lines(path)


def test_an_overlong_line_is_named_by_number_and_never_quoted(tmp_path: Path) -> None:
    path = tmp_path / "probes.txt"
    path.write_text(f"{BENIGN}\n" + "x" * (MAX_TEXT_CHARS + 1), encoding="utf-8")
    with pytest.raises(ImageRunError) as excinfo:
        read_probe_lines(path)
    assert str(excinfo.value) == f"line 2 is over {MAX_TEXT_CHARS} characters"


# --- sorting one result ----------------------------------------------------------


@pytest.mark.parametrize(
    ("status", "expected"),
    [
        (200, "accepted"),
        (201, "accepted"),
        (204, "accepted"),
        (400, "blocked"),
        (302, "errored"),
        (401, "errored"),
        (403, "errored"),
        (404, "errored"),
        (415, "errored"),
        (422, "errored"),
        (429, "errored"),
        (500, "errored"),
        (503, "errored"),
    ],
)
def test_a_status_is_sorted_by_the_documented_rule(status: int, expected: str) -> None:
    assert classify(_result(status)) == expected


def test_a_failed_connection_is_errored() -> None:
    assert classify(_result(None, "ConnectError: refused")) == "errored"


# --- running against the stub ----------------------------------------------------


def test_the_weak_stub_accepts_every_image(tmp_path: Path) -> None:
    summary = _run(tmp_path, _stub(weak_app))
    assert (summary.sent, summary.accepted, summary.blocked, summary.errored) == (
        3,
        3,
        0,
        0,
    )
    assert summary.status_codes == {"201": 3}


def test_the_hardened_stub_blocks_only_the_plain_injection(tmp_path: Path) -> None:
    summary = _run(tmp_path, _stub(hardened_app))
    assert (summary.sent, summary.accepted, summary.blocked, summary.errored) == (
        3,
        2,
        1,
        0,
    )
    assert summary.status_codes == {"201": 2, "400": 1}


def test_each_line_is_sent_as_one_multipart_png_upload(tmp_path: Path) -> None:
    seen: list[httpx2.Request] = []
    _run(tmp_path, _answering(201, seen), lines=[BENIGN, SPACED_INJECTION])
    assert len(seen) == 2
    for request in seen:
        assert request.url.path == "/ingest/image"
        assert request.headers["content-type"].startswith("multipart/form-data")
        assert b'name="file"; filename="probe.png"' in request.content
        assert b"\x89PNG" in request.content
        assert b"extracted_text" in request.content


def test_a_connection_failure_is_counted_as_errored(tmp_path: Path) -> None:
    summary = _run(tmp_path, _unreachable(), lines=[BENIGN, SPACED_INJECTION])
    assert (summary.accepted, summary.blocked, summary.errored) == (0, 0, 2)
    assert summary.status_codes == {NO_RESPONSE: 2}


@pytest.mark.parametrize("status", [401, 403, 404, 415, 422, 429, 500])
def test_a_refusal_other_than_400_never_counts_as_blocked(
    tmp_path: Path, status: int
) -> None:
    summary = _run(tmp_path, _answering(status), lines=[BENIGN, BENIGN])
    assert (summary.accepted, summary.blocked, summary.errored) == (0, 0, 2)
    assert summary.status_codes == {str(status): 2}


# --- the gate and the budget -----------------------------------------------------

REFUSED = [
    pytest.param(with_paths(VALID, ["/ingest/image"]), URL, id="suite not allowed"),
    pytest.param(with_suites('["image_prompt_injection"]'), URL, id="path not allowed"),
    pytest.param(IMAGE_ROE, "http://localhost:9999/ingest/image", id="wrong port"),
]


@pytest.mark.parametrize(("roe_text", "url"), REFUSED)
def test_a_refusal_by_the_gate_sends_nothing(
    tmp_path: Path, roe_text: str, url: str
) -> None:
    with pytest.raises(RoEViolationError):
        run_image_probes(
            _gate(tmp_path, roe_text),
            target_id="repo1-local",
            url=url,
            lines=LINES,
            client=_forbidden(),
        )


def test_the_budget_is_charged_once_per_image(tmp_path: Path) -> None:
    budget = _budget(total=5)
    _run(tmp_path, _stub(weak_app), budget=budget)
    assert budget.used == 3


def test_an_exhausted_budget_stops_the_run_and_returns_no_summary(
    tmp_path: Path,
) -> None:
    seen: list[httpx2.Request] = []
    budget = _budget(total=2)
    with pytest.raises(BudgetExhaustedError):
        _run(tmp_path, _answering(201, seen), budget=budget)
    assert len(seen) == 2
    assert budget.used == 2


# --- lines that cannot be used ---------------------------------------------------


def test_no_lines_sends_nothing(tmp_path: Path) -> None:
    with pytest.raises(ImageRunError, match="no probe lines"):
        _run(tmp_path, _forbidden(), lines=[])


@pytest.mark.parametrize(
    ("lines", "message"),
    [
        ([BENIGN, "   "], "probe 2 is empty"),
        (["x" * (MAX_TEXT_CHARS + 1)], f"probe 1 is over {MAX_TEXT_CHARS} characters"),
    ],
)
def test_an_unusable_line_stops_the_run_before_anything_is_sent(
    tmp_path: Path, lines: list[str], message: str
) -> None:
    with pytest.raises(ImageRunError) as excinfo:
        _run(tmp_path, _forbidden(), lines=lines)
    assert str(excinfo.value) == message


# --- the summary -----------------------------------------------------------------


def test_the_summary_json_holds_counts_and_no_text(tmp_path: Path) -> None:
    text = image_run_json(_run(tmp_path, _stub(hardened_app)))
    assert text.endswith("}\n")
    data = json.loads(text)
    assert set(data) == {
        "schema_version",
        "sent",
        "accepted",
        "blocked",
        "errored",
        "status_codes",
    }
    for line in LINES:
        assert line not in text
    assert "document_id" not in text


def _fields(**changes: object) -> dict[str, object]:
    base: dict[str, object] = {
        "schema_version": 1,
        "sent": 3,
        "accepted": 2,
        "blocked": 1,
        "errored": 0,
        "status_codes": {"201": 2, "400": 1},
    }
    return base | changes


def test_a_consistent_summary_is_accepted() -> None:
    assert ImageRunSummary.model_validate(_fields()).sent == 3


@pytest.mark.parametrize(
    ("changes", "message"),
    [
        ({"accepted": 3}, "do not add up to sent"),
        ({"status_codes": {"201": 2}}, "status code counts do not add up"),
        ({"sent": 0, "accepted": 0, "blocked": 0, "status_codes": {}}, "sent"),
        ({"errored": -1, "accepted": 3}, "errored"),
        ({"status_codes": {"201": 4, "400": -1}}, "status_codes"),
        ({"body": "x"}, "body"),
    ],
)
def test_a_summary_that_is_inconsistent_or_has_extras_is_refused(
    changes: dict[str, object], message: str
) -> None:
    with pytest.raises(ValidationError, match=message):
        ImageRunSummary.model_validate(_fields(**changes))
