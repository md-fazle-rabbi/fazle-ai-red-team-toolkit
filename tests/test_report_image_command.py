"""The report command with an image run summary."""

from pathlib import Path

import pytest

from redteam_toolkit.cli import main
from redteam_toolkit.image_run import SCHEMA_VERSION, ImageRunSummary, image_run_json
from tests.roe_samples import VALID

EXAMPLES = Path(__file__).resolve().parents[1] / "examples"
WITH_IMAGE = VALID.replace(
    'allowed_suites = ["prompt_injection", "pii_leakage"]',
    'allowed_suites = ["prompt_injection", "pii_leakage", "image_prompt_injection"]',
)


def _roe(tmp_path: Path, text: str = WITH_IMAGE) -> Path:
    path = tmp_path / "roe-image.toml"
    path.write_text(text, encoding="utf-8")
    return path


def _summary(
    tmp_path: Path, *, accepted: int = 0, blocked: int = 20, errored: int = 0
) -> Path:
    codes = {"201": accepted, "400": blocked, "503": errored}
    summary = ImageRunSummary(
        schema_version=SCHEMA_VERSION,
        sent=accepted + blocked + errored,
        accepted=accepted,
        blocked=blocked,
        errored=errored,
        status_codes={code: n for code, n in codes.items() if n},
    )
    path = tmp_path / "image-run.json"
    path.write_text(image_run_json(summary), encoding="utf-8")
    return path


def _report(roe: Path, image: Path, out: Path) -> int:
    return main(
        [
            "report",
            "--file",
            str(roe),
            "--image-run",
            str(image),
            "--out",
            str(out),
        ]
    )


def test_the_command_reports_an_image_run_alone(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    out = tmp_path / "report.md"
    code = _report(_roe(tmp_path), _summary(tmp_path), out)
    assert code == 0
    assert "report written" in capsys.readouterr().out
    text = out.read_text(encoding="utf-8")
    assert "### Image prompt injection (image_prompt_injection)" in text
    assert "Result: the bypass rate is below the limit." in text


def test_a_failing_image_run_is_still_reported(tmp_path: Path) -> None:
    out = tmp_path / "report.md"
    code = _report(_roe(tmp_path), _summary(tmp_path, accepted=2, blocked=18), out)
    assert code == 0
    assert "is not below 0.05." in out.read_text(encoding="utf-8")


def test_the_command_exits_3_for_a_missing_image_summary(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    out = tmp_path / "report.md"
    code = _report(_roe(tmp_path), tmp_path / "nope.json", out)
    assert code == 3
    assert "cannot report" in capsys.readouterr().err
    assert not out.exists()


def test_the_command_exits_3_for_an_invalid_image_summary(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    bad = tmp_path / "bad.json"
    bad.write_text("{}", encoding="utf-8")
    out = tmp_path / "report.md"
    code = _report(_roe(tmp_path), bad, out)
    assert code == 3
    assert "not a valid image run summary" in capsys.readouterr().err
    assert not out.exists()


def test_the_command_exits_3_when_the_run_cannot_be_judged(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    out = tmp_path / "report.md"
    code = _report(_roe(tmp_path), _summary(tmp_path, blocked=19, errored=1), out)
    assert code == 3
    assert "cannot be judged" in capsys.readouterr().err
    assert not out.exists()


def test_the_command_exits_3_when_the_suite_is_not_allowed(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    out = tmp_path / "report.md"
    code = _report(_roe(tmp_path, VALID), _summary(tmp_path), out)
    assert code == 3
    assert "not in allowed_suites" in capsys.readouterr().err
    assert not out.exists()


def test_the_image_example_engagement_works_with_an_image_summary(
    tmp_path: Path,
) -> None:
    out = tmp_path / "report.md"
    code = _report(EXAMPLES / "roe.stub-image.toml", _summary(tmp_path), out)
    assert code == 0
    assert "### Image prompt injection" in out.read_text(encoding="utf-8")
