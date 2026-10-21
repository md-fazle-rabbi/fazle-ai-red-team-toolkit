"""Tests for the score command."""

import json
from pathlib import Path

import pytest

from redteam_toolkit.cli import main


def _row(probe: str, uid: str, outputs: object) -> str:
    return json.dumps(
        {
            "entry_type": "attempt",
            "probe_classname": probe,
            "uuid": uid,
            "status": 2,
            "outputs": outputs,
        }
    )


def _report(tmp_path: Path, rows: list[str]) -> str:
    path = tmp_path / "r.report.jsonl"
    path.write_text("\n".join(rows) + "\n", encoding="utf-8")
    return str(path)


def test_a_clean_report_exits_zero(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    report = _report(
        tmp_path, [_row("a.One", "u1", [{"text": "Refunds take 30 days."}])]
    )
    assert main(["score", "--report", report]) == 0
    out = capsys.readouterr().out
    assert "a.One" in out
    assert "flagged attempts (any detector): 0" in out


def test_a_canary_in_an_answer_exits_one(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    report = _report(tmp_path, [_row("a.One", "u1", [{"text": "note SECRET-1 here"}])])
    assert main(["score", "--report", report, "--canary", "SECRET-1"]) == 1
    assert "flagged attempts (any detector): 1" in capsys.readouterr().out


def test_without_a_canary_option_only_personal_data_is_checked(tmp_path: Path) -> None:
    report = _report(tmp_path, [_row("a.One", "u1", [{"text": "note SECRET-1 here"}])])
    assert main(["score", "--report", report]) == 0


def test_personal_data_in_an_answer_exits_one(tmp_path: Path) -> None:
    report = _report(tmp_path, [_row("a.One", "u1", [{"text": "mail a@b.co"}])])
    assert main(["score", "--report", report]) == 1


def test_a_missing_report_exits_three(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    assert main(["score", "--report", str(tmp_path / "nope.jsonl")]) == 3
    assert "cannot score" in capsys.readouterr().err


def test_a_broken_report_exits_three(tmp_path: Path) -> None:
    assert main(["score", "--report", _report(tmp_path, ["not json"])]) == 3


def test_a_report_with_no_attempts_never_looks_clean(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    assert (
        main(
            [
                "score",
                "--report",
                _report(tmp_path, [json.dumps({"entry_type": "init"})]),
            ]
        )
        == 3
    )
    assert "no answered attempts" in capsys.readouterr().err


def test_a_report_where_every_attempt_was_skipped_never_looks_clean(
    tmp_path: Path,
) -> None:
    assert (
        main(["score", "--report", _report(tmp_path, [_row("a.One", "u1", [None])])])
        == 3
    )


def test_the_json_option_writes_a_summary_without_answer_text(tmp_path: Path) -> None:
    report = _report(tmp_path, [_row("a.One", "u1", [{"text": "mail a@b.co"}])])
    out = tmp_path / "summary.json"
    assert main(["score", "--report", report, "--json", str(out)]) == 1
    data = json.loads(out.read_text(encoding="utf-8"))
    assert data["flagged"] == 1
    assert data["evaluated"] == 1
    assert "a@b.co" not in out.read_text(encoding="utf-8")


def test_an_unwritable_summary_path_exits_three(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    report = _report(tmp_path, [_row("a.One", "u1", [{"text": "fine"}])])
    bad = tmp_path / "missing-dir" / "s.json"
    assert main(["score", "--report", report, "--json", str(bad)]) == 3
    assert "cannot write summary" in capsys.readouterr().err
