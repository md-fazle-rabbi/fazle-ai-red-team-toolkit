"""Tests for the command line entry point."""

import hashlib
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from redteam_toolkit.cli import ENV_VAR, main
from tests.roe_samples import VALID, with_window

URL = "http://localhost:8000/query"


def _live_file(tmp_path: Path) -> tuple[Path, str]:
    """Write a valid file whose window surrounds the current time."""
    now = datetime.now(UTC)
    text = with_window(VALID, now - timedelta(days=1), now + timedelta(days=1))
    path = tmp_path / "roe.toml"
    path.write_text(text, encoding="utf-8")
    return path, hashlib.sha256(text.encode("utf-8")).hexdigest()


@pytest.fixture(autouse=True)
def _clean_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv(ENV_VAR, raising=False)


def test_validate_accepts_a_good_file(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    path, digest = _live_file(tmp_path)
    assert main(["validate", "--file", str(path)]) == 0
    out = capsys.readouterr().out
    assert "valid: engagement=repo1-local-selftest" in out
    assert digest in out


def test_check_permits_an_authorized_request(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    path, _ = _live_file(tmp_path)
    args = ["check", "--file", str(path), "--target", "repo1-local"]
    assert main([*args, "--suite", "prompt_injection", "--url", URL]) == 0
    assert "permitted:" in capsys.readouterr().out


def test_check_refuses_a_wrong_target(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    path, _ = _live_file(tmp_path)
    code = main(
        ["check", "--file", str(path), "--target", "other", "--suite", "pii_leakage"]
    )
    assert code == 2
    assert "refused:" in capsys.readouterr().err


def test_check_refuses_a_path_outside_the_scope(tmp_path: Path) -> None:
    path, _ = _live_file(tmp_path)
    code = main(
        [
            "check",
            "--file",
            str(path),
            "--target",
            "repo1-local",
            "--suite",
            "pii_leakage",
            "--url",
            "http://localhost:8000/admin",
        ]
    )
    assert code == 2


def test_no_file_means_no_run(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["validate"]) == 2
    assert "No file, no run" in capsys.readouterr().err


def test_empty_environment_variable_counts_as_no_file(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setenv(ENV_VAR, "")
    assert main(["validate"]) == 2
    assert "No file, no run" in capsys.readouterr().err


def test_environment_variable_supplies_the_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path, _ = _live_file(tmp_path)
    monkeypatch.setenv(ENV_VAR, str(path))
    assert main(["validate"]) == 0


def test_invalid_file_is_refused(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    path = tmp_path / "roe.toml"
    path.write_text("not = [valid", encoding="utf-8")
    assert main(["validate", "--file", str(path)]) == 2
    assert "refused:" in capsys.readouterr().err


def test_unknown_suite_name_is_rejected_by_the_parser() -> None:
    with pytest.raises(SystemExit) as excinfo:
        main(["check", "--target", "repo1-local", "--suite", "nuke"])
    assert excinfo.value.code == 2
