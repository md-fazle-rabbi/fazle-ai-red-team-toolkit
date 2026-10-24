"""send_probe can send a multipart upload, and only through the gate.

The client here is wrapped around a mock transport, so nothing leaves the process and
no server is needed. The file bytes are a placeholder, not an image.
"""

from datetime import UTC, datetime, timedelta
from pathlib import Path

import httpx2
import pytest

from redteam_toolkit.roe import RoEGate, RoEViolationError, load_roe
from redteam_toolkit.runner import send_probe
from tests.roe_samples import VALID, with_window

URL = "http://localhost:8000/query"
FILES = {"file": ("probe.png", b"placeholder-bytes", "image/png")}


def _gate(tmp_path: Path) -> RoEGate:
    path = tmp_path / "roe.toml"
    now = datetime.now(UTC)
    path.write_text(
        with_window(VALID, now - timedelta(days=1), now + timedelta(days=1))
    )
    return RoEGate(load_roe(path))


def _recording_client(seen: list[httpx2.Request]) -> httpx2.Client:
    def handler(request: httpx2.Request) -> httpx2.Response:
        seen.append(request)
        return httpx2.Response(201, json={"ok": True})

    return httpx2.Client(transport=httpx2.MockTransport(handler))


def test_a_file_upload_is_sent_as_multipart(tmp_path: Path) -> None:
    seen: list[httpx2.Request] = []
    result = send_probe(
        _gate(tmp_path),
        target_id="repo1-local",
        suite="prompt_injection",
        url=URL,
        files=FILES,
        client=_recording_client(seen),
    )
    assert result.ok
    assert result.status_code == 201
    assert len(seen) == 1
    assert seen[0].headers["content-type"].startswith("multipart/form-data")
    assert b'name="file"; filename="probe.png"' in seen[0].content
    assert b"placeholder-bytes" in seen[0].content


def test_a_file_upload_is_refused_by_the_gate_and_sends_nothing(
    tmp_path: Path,
) -> None:
    seen: list[httpx2.Request] = []
    with pytest.raises(RoEViolationError):
        send_probe(
            _gate(tmp_path),
            target_id="repo1-local",
            suite="prompt_injection",
            url="http://localhost:9999/query",
            files=FILES,
            client=_recording_client(seen),
        )
    assert seen == []


@pytest.mark.parametrize("json_body", [None, {"question": "x"}])
def test_exactly_one_of_json_body_and_files_is_required(
    tmp_path: Path, json_body: dict[str, str] | None
) -> None:
    seen: list[httpx2.Request] = []
    files = FILES if json_body is not None else None
    with pytest.raises(ValueError, match="exactly one of json_body or files"):
        send_probe(
            _gate(tmp_path),
            target_id="repo1-local",
            suite="prompt_injection",
            url=URL,
            json_body=json_body,
            files=files,
            client=_recording_client(seen),
        )
    assert seen == []
