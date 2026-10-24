"""Tests for the robustness gate. The summaries here are made up, synthetic numbers."""

import json
from pathlib import Path
from typing import Any

import pytest

from redteam_toolkit.cli import main
from redteam_toolkit.robustness import (
    RobustnessError,
    evaluate_robustness,
    format_points,
    read_robustness_summary,
)

EXAMPLE = Path(__file__).resolve().parents[1] / "examples"
EXAMPLE = EXAMPLE / "robustness.synthetic-example.json"


def _write(tmp_path: Path, **change: Any) -> Path:
    body: dict[str, Any] = {
        "schema_version": 1,
        "data": "synthetic",
        "model": "logistic_regression",
        "attack": "fast_gradient_method",
        "rows": 500,
        "clean_accuracy": 0.9,
        "points": [
            {"epsilon": 0.05, "accuracy": 0.88},
            {"epsilon": 0.1, "accuracy": 0.84},
            {"epsilon": 0.3, "accuracy": 0.6},
        ],
    }
    body.update(change)
    path = tmp_path / "robustness.json"
    path.write_text(json.dumps(body), encoding="utf-8")
    return path


def _judge(tmp_path: Path, options: dict[str, Any] | None = None, **change: Any) -> Any:
    summary = read_robustness_summary(_write(tmp_path, **change))
    return evaluate_robustness(summary, **(options or {}))


def test_a_small_drop_passes(tmp_path: Path) -> None:
    result = _judge(tmp_path)
    assert result.passed
    assert result.reasons == ()
    assert result.accuracy_drop == 0.06
    assert result.accuracy == 0.84


def test_a_large_drop_fails(tmp_path: Path) -> None:
    result = _judge(tmp_path, {"epsilon": 0.3})
    assert not result.passed
    assert result.accuracy_drop == 0.3
    assert "accuracy drop 0.3000 at epsilon 0.3 is above 0.1" in result.reasons[0]


def test_a_drop_exactly_at_the_limit_passes(tmp_path: Path) -> None:
    points = [{"epsilon": 0.1, "accuracy": 0.8}]
    assert _judge(tmp_path, points=points).passed


def test_the_limit_can_be_changed(tmp_path: Path) -> None:
    assert _judge(tmp_path, {"epsilon": 0.3, "max_accuracy_drop": 0.5}).passed
    assert not _judge(tmp_path, {"max_accuracy_drop": 0.01}).passed


def test_an_unmeasured_epsilon_cannot_be_judged(tmp_path: Path) -> None:
    with pytest.raises(RobustnessError, match=r"no measurement at epsilon 0\.2"):
        _judge(tmp_path, {"epsilon": 0.2})


def test_too_few_rows_cannot_be_judged(tmp_path: Path) -> None:
    with pytest.raises(RobustnessError, match="fewer than the 100"):
        _judge(tmp_path, rows=99)


def test_the_row_floor_can_be_changed(tmp_path: Path) -> None:
    assert _judge(tmp_path, {"min_rows": 50}, rows=99).passed


@pytest.mark.parametrize(
    "change",
    [
        {"data": "real"},
        {"rows": 0},
        {"clean_accuracy": 1.2},
        {"points": []},
        {"points": [{"epsilon": 0, "accuracy": 0.5}]},
        {
            "points": [
                {"epsilon": 0.1, "accuracy": 0.5},
                {"epsilon": 0.1, "accuracy": 0.4},
            ]
        },
        {
            "points": [
                {"epsilon": 0.2, "accuracy": 0.5},
                {"epsilon": 0.1, "accuracy": 0.4},
            ]
        },
        {"extra": 1},
        {"model": "bad/name"},
    ],
)
def test_an_invalid_summary_is_rejected(tmp_path: Path, change: dict[str, Any]) -> None:
    with pytest.raises(RobustnessError, match="not a valid"):
        read_robustness_summary(_write(tmp_path, **change))


def test_the_wrong_schema_version_is_rejected(tmp_path: Path) -> None:
    with pytest.raises(RobustnessError, match="schema version 2"):
        read_robustness_summary(_write(tmp_path, schema_version=2))


def test_a_file_that_is_not_json_is_rejected(tmp_path: Path) -> None:
    path = tmp_path / "f.json"
    path.write_text("nope", encoding="utf-8")
    with pytest.raises(RobustnessError, match="not a valid"):
        read_robustness_summary(path)


def test_a_file_that_is_not_text_is_rejected(tmp_path: Path) -> None:
    path = tmp_path / "f.json"
    path.write_bytes(b"\xff\xfe\x00")
    with pytest.raises(RobustnessError, match="not text"):
        read_robustness_summary(path)


def test_the_point_table_lists_every_epsilon(tmp_path: Path) -> None:
    text = format_points(read_robustness_summary(_write(tmp_path)))
    assert "model=logistic_regression attack=fast_gradient_method" in text
    assert "clean_accuracy=0.9000" in text
    assert "epsilon=0.3 accuracy=0.6000" in text


def test_the_example_is_valid_and_passes_at_the_default_epsilon() -> None:
    result = evaluate_robustness(read_robustness_summary(EXAMPLE))
    assert result.passed
    assert result.accuracy_drop == 0.06


def test_the_command_passes(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["robustness-gate", "--summary", str(_write(tmp_path))]) == 0
    out = capsys.readouterr().out
    assert "epsilon=0.1 accuracy_drop=0.0600" in out
    assert "robustness gate: pass" in out


def test_the_command_fails_on_a_drop(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    path = _write(tmp_path)
    assert main(["robustness-gate", "--summary", str(path), "--epsilon", "0.3"]) == 1
    assert "robustness gate: fail, accuracy drop" in capsys.readouterr().out


def test_the_command_takes_limits(tmp_path: Path) -> None:
    path = str(_write(tmp_path))
    args = ["robustness-gate", "--summary", path, "--epsilon", "0.3"]
    assert main([*args, "--max-accuracy-drop", "0.5"]) == 0
    assert main(["robustness-gate", "--summary", path, "--min-rows", "1000"]) == 3


@pytest.mark.parametrize("case", ["missing", "bad", "no_epsilon"])
def test_the_command_exits_3_when_it_cannot_judge(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], case: str
) -> None:
    bad = tmp_path / "bad.json"
    bad.write_text("{", encoding="utf-8")
    path = {
        "missing": tmp_path / "nope.json",
        "bad": bad,
        "no_epsilon": _write(tmp_path),
    }[case]
    args = ["robustness-gate", "--summary", str(path)]
    if case == "no_epsilon":
        args += ["--epsilon", "0.2"]
    assert main(args) == 3
    captured = capsys.readouterr()
    assert "cannot judge" in captured.err
    assert "pass" not in captured.out


def test_a_limit_above_one_is_an_argument_error(tmp_path: Path) -> None:
    path = str(_write(tmp_path))
    with pytest.raises(SystemExit) as caught:
        main(["robustness-gate", "--summary", path, "--max-accuracy-drop", "2"])
    assert caught.value.code == 2
