"""Tests for scoring answers from the neutral answers file."""

import json
from pathlib import Path

import pytest

from redteam_toolkit.cli import main
from redteam_toolkit.scoring import Attempt, ReportError, read_answers_file


def _write(tmp_path: Path, rows: list[str]) -> Path:
    path = tmp_path / "answers.jsonl"
    path.write_text("\n".join(rows) + "\n", encoding="utf-8")
    return path


def _line(probe: object, answer: object) -> str:
    return json.dumps({"probe": probe, "answer": answer})


def test_answers_are_read_and_a_missing_answer_counts_as_skipped(
    tmp_path: Path,
) -> None:
    path = _write(
        tmp_path,
        [_line("a.One", "fine"), "", _line("a.One", None), _line("b.Two", "")],
    )
    assert read_answers_file(path) == [
        Attempt("a.One", ("fine",)),
        Attempt("a.One", ()),
        Attempt("b.Two", ()),
    ]


def test_other_fields_are_ignored_and_never_reach_the_attempt(tmp_path: Path) -> None:
    row = json.dumps({"probe": "a.One", "answer": "ok", "prompt": "PROMPT-TEXT"})
    (attempt,) = read_answers_file(_write(tmp_path, [row]))
    assert "PROMPT-TEXT" not in repr(attempt)


@pytest.mark.parametrize(
    "row",
    [
        "not json",
        "[1, 2]",
        json.dumps({"answer": "x"}),
        json.dumps({"probe": 3, "answer": "x"}),
        json.dumps({"probe": "a.One", "answer": 5}),
    ],
)
def test_a_badly_shaped_line_is_refused_with_its_number(
    tmp_path: Path, row: str
) -> None:
    with pytest.raises(ReportError, match="line 1"):
        read_answers_file(_write(tmp_path, [row]))


def test_the_command_scores_an_answers_file(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    path = _write(tmp_path, [_line("a.One", "mail a@b.co"), _line("a.One", "fine")])
    assert main(["score", "--answers", str(path)]) == 1
    out = capsys.readouterr().out
    assert "a.One" in out
    assert "flagged attempts (any detector): 1" in out


def test_the_command_checks_a_canary_in_an_answers_file(tmp_path: Path) -> None:
    path = _write(tmp_path, [_line("a.One", "note SECRET-1 here")])
    assert main(["score", "--answers", str(path), "--canary", "SECRET-1"]) == 1
    assert main(["score", "--answers", str(path)]) == 0


def test_an_answers_file_with_no_answers_never_looks_clean(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    path = _write(tmp_path, [_line("a.One", None), _line("a.One", "")])
    assert main(["score", "--answers", str(path)]) == 3
    assert "no answered attempts" in capsys.readouterr().err


def test_an_answers_file_that_cannot_be_read_exits_three(tmp_path: Path) -> None:
    assert main(["score", "--answers", str(tmp_path / "nope.jsonl")]) == 3
    assert main(["score", "--answers", str(_write(tmp_path, ["not json"]))]) == 3


def test_the_command_needs_exactly_one_input(tmp_path: Path) -> None:
    path = str(_write(tmp_path, [_line("a.One", "fine")]))
    with pytest.raises(SystemExit):
        main(["score"])
    with pytest.raises(SystemExit):
        main(["score", "--report", path, "--answers", path])
