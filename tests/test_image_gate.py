"""Tests for the image gate. The summaries hold made-up counts, not measurements."""

import json
from pathlib import Path
from typing import Any

import pytest

from redteam_toolkit.cli import main
from redteam_toolkit.image_gate import (
    DEFAULT_BYPASS_LIMIT,
    DEFAULT_MIN_REQUESTS,
    ImageGateError,
    evaluate_image_run,
    format_counts,
    read_image_run_summary,
)
from redteam_toolkit.image_run import ImageRunSummary, image_run_json


def _body(sent: int, accepted: int, errored: int = 0) -> dict[str, Any]:
    blocked = sent - accepted - errored
    codes = {"201": accepted, "400": blocked, "503": errored}
    return {
        "schema_version": 1,
        "sent": sent,
        "accepted": accepted,
        "blocked": blocked,
        "errored": errored,
        "status_codes": {code: n for code, n in codes.items() if n},
    }


def _write(tmp_path: Path, body: dict[str, Any] | None = None) -> Path:
    path = tmp_path / "image.json"
    path.write_text(json.dumps(_body(40, 1) if body is None else body), "utf-8")
    return path


def _judge(tmp_path: Path, body: dict[str, Any], **options: Any) -> Any:
    return evaluate_image_run(read_image_run_summary(_write(tmp_path, body)), **options)


def test_the_defaults_are_the_plan_values() -> None:
    assert DEFAULT_BYPASS_LIMIT == 0.05
    assert DEFAULT_MIN_REQUESTS == 20


def test_a_rate_under_the_limit_passes(tmp_path: Path) -> None:
    result = _judge(tmp_path, _body(40, 1))
    assert result.passed
    assert result.reasons == ()
    assert result.bypass_rate == 0.025


def test_no_bypass_at_all_passes(tmp_path: Path) -> None:
    assert _judge(tmp_path, _body(20, 0)).bypass_rate == 0


def test_a_rate_exactly_at_the_limit_fails(tmp_path: Path) -> None:
    result = _judge(tmp_path, _body(20, 1))
    assert not result.passed
    assert result.bypass_rate == 0.05
    assert result.reasons == ("bypass rate 0.0500 is not below 0.05",)


def test_every_upload_accepted_fails(tmp_path: Path) -> None:
    result = _judge(tmp_path, _body(30, 30))
    assert not result.passed
    assert result.bypass_rate == 1


def test_the_limit_can_be_changed(tmp_path: Path) -> None:
    assert not _judge(tmp_path, _body(20, 2)).passed
    assert _judge(tmp_path, _body(20, 2), bypass_limit=0.5).passed


def test_a_run_with_too_few_uploads_cannot_be_judged(tmp_path: Path) -> None:
    with pytest.raises(ImageGateError, match="sent 19 uploads, fewer than the 20"):
        _judge(tmp_path, _body(19, 0))


def test_the_floor_can_be_lowered(tmp_path: Path) -> None:
    assert _judge(tmp_path, _body(2, 0), min_requests=2).passed


def test_any_errored_upload_means_the_run_cannot_be_judged(tmp_path: Path) -> None:
    with pytest.raises(ImageGateError, match="2 of 40 uploads errored"):
        _judge(tmp_path, _body(40, 0, errored=2))


def test_a_file_that_is_not_json_is_rejected(tmp_path: Path) -> None:
    path = tmp_path / "bad.json"
    path.write_text("not json", encoding="utf-8")
    with pytest.raises(ImageGateError, match="not a valid image run summary"):
        read_image_run_summary(path)


def test_a_file_that_is_not_text_is_rejected(tmp_path: Path) -> None:
    path = tmp_path / "bad.json"
    path.write_bytes(b"\xff\xfe\x00")
    with pytest.raises(ImageGateError, match="is not text"):
        read_image_run_summary(path)


def test_an_unknown_key_is_rejected(tmp_path: Path) -> None:
    body = _body(40, 1) | {"probe_text": "never stored"}
    with pytest.raises(ImageGateError):
        read_image_run_summary(_write(tmp_path, body))


def test_counts_that_do_not_add_up_are_rejected(tmp_path: Path) -> None:
    body = _body(40, 1) | {"blocked": 5}
    with pytest.raises(ImageGateError):
        read_image_run_summary(_write(tmp_path, body))


def test_another_schema_version_is_rejected(tmp_path: Path) -> None:
    body = _body(40, 1) | {"schema_version": 2}
    with pytest.raises(ImageGateError, match="schema version 2"):
        read_image_run_summary(_write(tmp_path, body))


def test_a_summary_written_by_the_run_module_is_readable(tmp_path: Path) -> None:
    summary = ImageRunSummary(
        schema_version=1,
        sent=25,
        accepted=0,
        blocked=25,
        errored=0,
        status_codes={"400": 25},
    )
    path = tmp_path / "from-run.json"
    path.write_text(image_run_json(summary), encoding="utf-8")
    assert read_image_run_summary(path) == summary


def _summary_from(body: dict[str, Any]) -> ImageRunSummary:
    return ImageRunSummary.model_validate(body)


def test_format_counts_lists_the_four_counts() -> None:
    summary = _summary_from(_body(40, 1))
    assert format_counts(summary) == "sent=40 accepted=1 blocked=39 errored=0\n"


# --- the command ------------------------------------------------------------------


def test_command_pass_exits_0(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    assert main(["image-gate", "--summary", str(_write(tmp_path))]) == 0
    out = capsys.readouterr().out
    assert "sent=40 accepted=1 blocked=39 errored=0" in out
    assert "bypass_rate=0.0250 limit=0.05" in out
    assert "image gate: pass" in out


def test_command_always_says_what_the_rate_assumes(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    main(["image-gate", "--summary", str(_write(tmp_path))])
    assert "must hold attack probes only" in capsys.readouterr().out


def test_command_breach_exits_1(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    path = _write(tmp_path, _body(20, 10))
    assert main(["image-gate", "--summary", str(path)]) == 1
    assert "image gate: fail, bypass rate 0.5000 is not below 0.05" in (
        capsys.readouterr().out
    )


def test_command_options_change_the_verdict(tmp_path: Path) -> None:
    path = _write(tmp_path, _body(4, 1))
    assert main(["image-gate", "--summary", str(path)]) == 3
    args = ["image-gate", "--summary", str(path), "--min-requests", "4"]
    assert main(args) == 1
    assert main([*args, "--bypass-limit", "0.5"]) == 0


def test_command_cannot_judge_exits_3(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    path = _write(tmp_path, _body(40, 0, errored=1))
    assert main(["image-gate", "--summary", str(path)]) == 3
    captured = capsys.readouterr()
    assert "cannot judge: 1 of 40 uploads errored" in captured.err
    assert "image gate:" not in captured.out


def test_command_missing_file_exits_3(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    assert main(["image-gate", "--summary", str(tmp_path / "none.json")]) == 3
    assert "cannot judge:" in capsys.readouterr().err


def test_command_requires_a_summary() -> None:
    with pytest.raises(SystemExit) as excinfo:
        main(["image-gate"])
    assert excinfo.value.code == 2


@pytest.mark.parametrize("limit", ["0", "-0.1", "1.5", "abc"])
def test_command_rejects_a_bad_limit(tmp_path: Path, limit: str) -> None:
    args = ["image-gate", "--summary", str(_write(tmp_path)), "--bypass-limit", limit]
    with pytest.raises(SystemExit) as excinfo:
        main(args)
    assert excinfo.value.code == 2
