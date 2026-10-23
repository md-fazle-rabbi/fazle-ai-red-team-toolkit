"""Tests for the fairness gate. The summaries here are made up, synthetic numbers."""

import json
from pathlib import Path
from typing import Any

import pytest

from redteam_toolkit.cli import main
from redteam_toolkit.fairness import (
    FairnessError,
    evaluate,
    format_groups,
    read_fairness_summary,
)


def _group(
    name: str,
    *,
    count: int = 100,
    sel: float = 0.5,
    tpr: float | None = 0.8,
    fpr: float | None = 0.1,
) -> dict[str, Any]:
    return {
        "group": name,
        "count": count,
        "selection_rate": sel,
        "true_positive_rate": tpr,
        "false_positive_rate": fpr,
    }


def _write(tmp_path: Path, groups: list[dict[str, Any]], **extra: Any) -> Path:
    body: dict[str, Any] = {
        "schema_version": 1,
        "attribute": "group",
        "data": "synthetic",
        "groups": groups,
    }
    body.update(extra)
    path = tmp_path / "fairness.json"
    path.write_text(json.dumps(body), encoding="utf-8")
    return path


def _judge(tmp_path: Path, groups: list[dict[str, Any]], **options: Any) -> Any:
    summary = read_fairness_summary(_write(tmp_path, groups))
    return evaluate(summary, **options)


def test_similar_groups_pass(tmp_path: Path) -> None:
    result = _judge(tmp_path, [_group("a"), _group("b", sel=0.55, tpr=0.75)])
    assert result.passed
    assert result.reasons == ()
    assert result.parity_difference == 0.05
    assert result.equalized_odds_difference == 0.05


def test_a_selection_gap_fails_parity(tmp_path: Path) -> None:
    result = _judge(tmp_path, [_group("a"), _group("b", sel=0.7)])
    assert not result.passed
    assert len(result.reasons) == 1
    assert "demographic parity difference 0.2000 is above 0.1" in result.reasons[0]


def test_a_true_positive_gap_fails_equalized_odds(tmp_path: Path) -> None:
    result = _judge(tmp_path, [_group("a"), _group("b", tpr=0.5)])
    assert not result.passed
    assert result.equalized_odds_difference == 0.3
    assert "equalized odds difference 0.3000" in result.reasons[0]


def test_a_false_positive_gap_fails_equalized_odds(tmp_path: Path) -> None:
    result = _judge(tmp_path, [_group("a"), _group("b", fpr=0.4)])
    assert not result.passed
    assert result.equalized_odds_difference == 0.3


def test_both_failures_are_listed(tmp_path: Path) -> None:
    result = _judge(tmp_path, [_group("a"), _group("b", sel=0.9, tpr=0.4)])
    assert len(result.reasons) == 2


def test_a_gap_exactly_at_the_limit_passes(tmp_path: Path) -> None:
    result = _judge(tmp_path, [_group("a", sel=0.5), _group("b", sel=0.6)])
    assert result.passed


def test_the_limits_can_be_changed(tmp_path: Path) -> None:
    groups = [_group("a"), _group("b", sel=0.7)]
    assert _judge(tmp_path, groups, max_parity_difference=0.3).passed
    assert not _judge(tmp_path, groups, max_parity_difference=0.01).passed


def test_three_groups_use_the_widest_gap(tmp_path: Path) -> None:
    groups = [_group("a", sel=0.5), _group("b", sel=0.55), _group("c", sel=0.68)]
    assert _judge(tmp_path, groups).parity_difference == 0.18


def test_one_group_cannot_be_judged(tmp_path: Path) -> None:
    with pytest.raises(FairnessError, match="at least two groups"):
        _judge(tmp_path, [_group("a")])


def test_a_small_group_cannot_be_judged(tmp_path: Path) -> None:
    with pytest.raises(FairnessError, match=r"fewer than 30 rows.*b"):
        _judge(tmp_path, [_group("a"), _group("b", count=29)])


def test_the_group_size_floor_can_be_changed(tmp_path: Path) -> None:
    groups = [_group("a"), _group("b", count=29)]
    assert _judge(tmp_path, groups, min_group_size=10).passed


@pytest.mark.parametrize("missing", ["tpr", "fpr"])
def test_missing_error_rates_cannot_be_judged(tmp_path: Path, missing: str) -> None:
    gap: dict[str, Any] = {missing: None}
    with pytest.raises(FairnessError, match="true positive rate"):
        _judge(tmp_path, [_group("a", **gap), _group("b", **gap)])


def test_a_group_with_one_missing_rate_still_counts_for_the_rest(
    tmp_path: Path,
) -> None:
    groups = [_group("a"), _group("b"), _group("c", tpr=None, fpr=None)]
    assert _judge(tmp_path, groups).passed


def test_real_data_is_rejected(tmp_path: Path) -> None:
    path = _write(tmp_path, [_group("a"), _group("b")], data="real")
    with pytest.raises(FairnessError, match="not a valid"):
        read_fairness_summary(path)


def test_a_duplicate_group_is_rejected(tmp_path: Path) -> None:
    with pytest.raises(FairnessError, match="not a valid"):
        read_fairness_summary(_write(tmp_path, [_group("a"), _group("a")]))


def test_an_unknown_field_is_rejected(tmp_path: Path) -> None:
    with pytest.raises(FairnessError, match="not a valid"):
        read_fairness_summary(_write(tmp_path, [_group("a")], parity=0.0))


def test_a_rate_outside_zero_to_one_is_rejected(tmp_path: Path) -> None:
    with pytest.raises(FairnessError, match="not a valid"):
        read_fairness_summary(_write(tmp_path, [_group("a", sel=1.2)]))


def test_the_wrong_schema_version_is_rejected(tmp_path: Path) -> None:
    path = _write(tmp_path, [_group("a"), _group("b")], schema_version=2)
    with pytest.raises(FairnessError, match="schema version 2"):
        read_fairness_summary(path)


def test_a_file_that_is_not_json_is_rejected(tmp_path: Path) -> None:
    path = tmp_path / "f.json"
    path.write_text("nope", encoding="utf-8")
    with pytest.raises(FairnessError, match="not a valid"):
        read_fairness_summary(path)


def test_a_file_that_is_not_text_is_rejected(tmp_path: Path) -> None:
    path = tmp_path / "f.json"
    path.write_bytes(b"\xff\xfe\x00")
    with pytest.raises(FairnessError, match="not text"):
        read_fairness_summary(path)


def test_the_group_table_shows_every_rate(tmp_path: Path) -> None:
    summary = read_fairness_summary(
        _write(tmp_path, [_group("a"), _group("b", tpr=None)])
    )
    text = format_groups(summary)
    assert "attribute=group data=synthetic" in text
    assert "group=a count=100 selection_rate=0.5000" in text
    assert "true_positive_rate=n/a" in text


def test_the_command_passes(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    path = _write(tmp_path, [_group("a"), _group("b", sel=0.55)])
    assert main(["fairness-gate", "--summary", str(path)]) == 0
    out = capsys.readouterr().out
    assert "demographic_parity_difference=0.0500" in out
    assert "fairness gate: pass" in out


def test_the_command_fails_on_a_gap(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    path = _write(tmp_path, [_group("a"), _group("b", sel=0.9)])
    assert main(["fairness-gate", "--summary", str(path)]) == 1
    assert "fairness gate: fail, demographic parity" in capsys.readouterr().out


def test_the_command_takes_limits(tmp_path: Path) -> None:
    path = _write(tmp_path, [_group("a"), _group("b", sel=0.9)])
    args = ["fairness-gate", "--summary", str(path)]
    assert main([*args, "--max-parity-difference", "0.5"]) == 0
    loose = [*args, "--max-parity-difference", "0.5"]
    assert main([*loose, "--max-equalized-odds-difference", "0.01"]) == 0
    gap = _write(tmp_path, [_group("a"), _group("b", tpr=0.5)])
    base = ["fairness-gate", "--summary", str(gap), "--max-parity-difference", "0.5"]
    assert main(base) == 1
    assert main([*base, "--max-equalized-odds-difference", "0.5"]) == 0
    small = _write(tmp_path, [_group("a", count=5), _group("b", count=5)])
    assert main(["fairness-gate", "--summary", str(small)]) == 3
    assert (
        main(["fairness-gate", "--summary", str(small), "--min-group-size", "5"]) == 0
    )


@pytest.mark.parametrize("case", ["missing", "one_group", "bad"])
def test_the_command_exits_3_when_it_cannot_judge(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], case: str
) -> None:
    bad = tmp_path / "bad.json"
    bad.write_text("{", encoding="utf-8")
    path = {
        "missing": tmp_path / "nope.json",
        "one_group": _write(tmp_path, [_group("a")]),
        "bad": bad,
    }[case]
    assert main(["fairness-gate", "--summary", str(path)]) == 3
    captured = capsys.readouterr()
    assert "cannot judge" in captured.err
    assert "pass" not in captured.out


def test_a_limit_above_one_is_an_argument_error(tmp_path: Path) -> None:
    path = _write(tmp_path, [_group("a"), _group("b")])
    with pytest.raises(SystemExit) as caught:
        main(["fairness-gate", "--summary", str(path), "--max-parity-difference", "2"])
    assert caught.value.code == 2


def test_the_example_summary_is_valid_and_passes() -> None:
    root = Path(__file__).resolve().parents[1]
    summary = read_fairness_summary(
        root / "examples" / "fairness.synthetic-example.json"
    )
    result = evaluate(summary)
    assert result.passed
    assert result.parity_difference == 0.04
