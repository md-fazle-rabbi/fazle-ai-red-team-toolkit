"""The --header-env and --timeout options on image-probe and exploit-run.

The target is a recording stand-in, reached in process. Nothing here opens a socket.
The tenant value is made up. The probes come from the committed exploit library and
the benign line the image tests already use, so this module adds no attack content.
"""

from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path

import httpx2
import pytest

from redteam_toolkit.cli import ENV_VAR, main
from redteam_toolkit.exploit_library import load_library
from redteam_toolkit.runner import DEFAULT_TIMEOUT_SECONDS
from tests.roe_samples import change, with_paths, with_suites, with_window
from tests.test_stub_image import BENIGN

IMAGE_URL = "http://localhost:8000/ingest/image"
QUERY_URL = "http://localhost:8000/query"
CANARY = "CANARY-9f2c1e-SYSTEM-PROMPT"
FAKE = "00000000-0000-4000-8000-0000000000aa"
ENV_NAME = "REPO1_TEST_TENANT"
HEADER_ARGS = ["--header-env", f"X-Tenant-ID={ENV_NAME}", "--timeout", "30"]
LINES = [BENIGN, BENIGN, BENIGN]
LIBRARY = Path(__file__).parent.parent / "exploits" / "library.toml"
IMAGE_ROE = with_paths(with_suites('["image_prompt_injection"]'), ["/ingest/image"])
EXPLOIT_ROE = with_paths(
    with_suites('["prompt_injection", "jailbreak", "pii_leakage"]'), ["/query"]
)
COMMANDS = ["image-probe", "exploit-run"]
# Why: the tests replace httpx2.Client, so keep the real one to build stand-ins.
REAL_CLIENT = httpx2.Client
PATCH_TARGET = "redteam_toolkit.runner.httpx2.Client"


@dataclass
class Seen:
    builds: list[tuple[dict[str, str] | None, float]] = field(default_factory=list)
    requests: list[httpx2.Request] = field(default_factory=list)


@pytest.fixture(autouse=True)
def _environment(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv(ENV_VAR, raising=False)
    monkeypatch.setenv(ENV_NAME, FAKE)


def _use_recorder(monkeypatch: pytest.MonkeyPatch) -> Seen:
    """Record every client build and every request. The answer is a harmless one."""
    seen = Seen()

    def handler(request: httpx2.Request) -> httpx2.Response:
        seen.requests.append(request)
        return httpx2.Response(201, json={"answer": "ok"})

    def build(
        *,
        timeout: float,
        follow_redirects: bool,
        trust_env: bool,
        headers: dict[str, str] | None = None,
    ) -> httpx2.Client:
        seen.builds.append((headers, timeout))
        assert follow_redirects is False
        assert trust_env is False
        return REAL_CLIENT(transport=httpx2.MockTransport(handler), headers=headers)

    monkeypatch.setattr(PATCH_TARGET, build)
    return seen


def _roe_file(tmp_path: Path, text: str) -> Path:
    now = datetime.now(UTC)
    fast = change(text, "requests_per_minute = 2", "requests_per_minute = 6000")
    live = with_window(fast, now - timedelta(days=1), now + timedelta(days=1))
    path = tmp_path / "roe.toml"
    path.write_text(live, encoding="utf-8")
    return path


def _args(
    command: str,
    tmp_path: Path,
    extra: list[str] | None = None,
    target: str = "repo1-local",
) -> list[str]:
    extra = extra or []
    if command == "image-probe":
        probes = tmp_path / "probes.txt"
        probes.write_text("\n".join(LINES), encoding="utf-8")
        roe = _roe_file(tmp_path, IMAGE_ROE)
        return [
            "image-probe",
            *["--file", str(roe), "--target", target, "--url", IMAGE_URL],
            *["--probes", str(probes), *extra],
        ]
    roe = _roe_file(tmp_path, EXPLOIT_ROE)
    return [
        "exploit-run",
        *["--file", str(roe), "--target", target, "--url", QUERY_URL],
        *["--library", str(LIBRARY), "--canary", CANARY, *extra],
    ]


def _expected_requests(command: str) -> int:
    if command == "image-probe":
        return len(LINES)
    return len(load_library(LIBRARY).exploit)


@pytest.mark.parametrize("command", COMMANDS)
def test_the_options_build_one_shared_client_and_the_header_goes_out(
    command: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    seen = _use_recorder(monkeypatch)
    out_json = tmp_path / "summary.json"
    assert main(_args(command, tmp_path, [*HEADER_ARGS, "--json", str(out_json)])) == 0
    assert seen.builds == [({"X-Tenant-ID": FAKE}, 30.0)]
    assert len(seen.requests) == _expected_requests(command)
    assert {request.headers["x-tenant-id"] for request in seen.requests} == {FAKE}
    shown = capsys.readouterr()
    for text in (shown.out, shown.err, out_json.read_text(encoding="utf-8")):
        assert FAKE not in text


@pytest.mark.parametrize("command", COMMANDS)
def test_without_the_options_each_request_builds_its_own_plain_client(
    command: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    seen = _use_recorder(monkeypatch)
    assert main(_args(command, tmp_path)) == 0
    assert len(seen.builds) == _expected_requests(command)
    assert all(
        headers is None and timeout == DEFAULT_TIMEOUT_SECONDS
        for headers, timeout in seen.builds
    )
    assert all("x-tenant-id" not in request.headers for request in seen.requests)


@pytest.mark.parametrize("command", COMMANDS)
def test_a_refusal_still_sends_nothing_when_the_options_are_given(
    command: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    seen = _use_recorder(monkeypatch)
    assert main(_args(command, tmp_path, HEADER_ARGS, target="other")) == 2
    assert seen.requests == []


@pytest.mark.parametrize("command", COMMANDS)
def test_a_missing_variable_exits_3_and_names_the_variable_only(
    command: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    seen = _use_recorder(monkeypatch)
    monkeypatch.delenv(ENV_NAME)
    assert main(_args(command, tmp_path, HEADER_ARGS)) == 3
    assert f"{ENV_NAME} is not set" in capsys.readouterr().err
    assert seen.builds == []
    assert seen.requests == []


@pytest.mark.parametrize("command", COMMANDS)
def test_a_pasted_value_is_refused_and_never_echoed(
    command: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    seen = _use_recorder(monkeypatch)
    extra = ["--header-env", f"Authorization=Bearer {FAKE}"]
    assert main(_args(command, tmp_path, extra)) == 3
    err = capsys.readouterr().err
    assert "must look like" in err
    assert FAKE not in err
    assert seen.requests == []


@pytest.mark.parametrize("command", COMMANDS)
def test_a_timeout_above_the_ceiling_exits_3(
    command: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    seen = _use_recorder(monkeypatch)
    assert main(_args(command, tmp_path, ["--timeout", "500"])) == 3
    assert "timeout must be" in capsys.readouterr().err
    assert seen.requests == []
