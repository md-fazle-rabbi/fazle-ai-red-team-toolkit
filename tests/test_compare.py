"""Tests for comparing two run summaries."""

import json
from pathlib import Path

import pytest

from redteam_toolkit.cli import main
from redteam_toolkit.scoring import ProbeScore
from redteam_toolkit.summary import (
    CAVEAT,
    SummaryError,
    format_comparison,
    read_summary,
    summarize,
    summary_json,
)

NONE = {"canary_leak": 0, "pii_exposed": 0}
PII = {"canary_leak": 0, "pii_exposed": 1}


def _write(path: Path, scores: list[ProbeScore]) -> str:
    path.write_text(summary_json(summarize(scores)), encoding="utf-8")
    return str(path)


def test_the_table_shows_both_sides_and_the_totals() -> None:
    before = summarize([ProbeScore("a.One", 8, 0, PII, 1)])
    after = summarize([ProbeScore("a.One", 8, 2, NONE, 0)])
    out = format_comparison(before, after)
    assert "8 > 8" in out
    assert "0 > 2" in out
    assert "1 > 0" in out
    assert "12.5% > 0.0%" in out
    assert out.count("a.One") == 1
    assert "all probes" in out
    assert CAVEAT in out


def test_a_probe_on_one_side_only_shows_a_dash_on_the_other() -> None:
    before = summarize([ProbeScore("a.One", 4, 0, NONE, 0)])
    after = summarize([ProbeScore("b.Two", 4, 0, NONE, 0)])
    out = format_comparison(before, after)
    assert "4 > -" in out
    assert "- > 4" in out


def test_a_missing_rate_shows_as_a_dash() -> None:
    before = summarize([ProbeScore("a.One", 0, 3, NONE, 0)])
    after = summarize([ProbeScore("a.One", 2, 0, NONE, 0)])
    assert "n/a > 0.0%" in format_comparison(before, after)


def test_read_summary_round_trips(tmp_path: Path) -> None:
    path = Path(_write(tmp_path / "s.json", [ProbeScore("a.One", 1, 0, NONE, 0)]))
    assert read_summary(path).probes[0].probe == "a.One"


def test_read_summary_refuses_a_file_that_is_not_a_summary(tmp_path: Path) -> None:
    path = tmp_path / "s.json"
    path.write_text("{}", encoding="utf-8")
    with pytest.raises(SummaryError, match="not a valid summary"):
        read_summary(path)


def test_read_summary_refuses_binary_content(tmp_path: Path) -> None:
    path = tmp_path / "s.json"
    path.write_bytes(b"\xff\xfe\x00")
    with pytest.raises(SummaryError, match="is not text"):
        read_summary(path)


def test_read_summary_refuses_another_schema_version(tmp_path: Path) -> None:
    path = Path(_write(tmp_path / "s.json", [ProbeScore("a.One", 1, 0, NONE, 0)]))
    data = json.loads(path.read_text(encoding="utf-8"))
    data["schema_version"] = 99
    path.write_text(json.dumps(data), encoding="utf-8")
    with pytest.raises(SummaryError, match="schema version 99"):
        read_summary(path)


def test_the_compare_command_prints_the_table_and_exits_zero(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    before = _write(tmp_path / "a.json", [ProbeScore("a.One", 8, 0, PII, 1)])
    after = _write(tmp_path / "b.json", [ProbeScore("a.One", 8, 0, NONE, 0)])
    assert main(["compare", "--before", before, "--after", after]) == 0
    assert "1 > 0" in capsys.readouterr().out


def test_the_compare_command_exits_three_for_a_missing_file(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    ok = _write(tmp_path / "a.json", [ProbeScore("a.One", 1, 0, NONE, 0)])
    assert main(["compare", "--before", ok, "--after", str(tmp_path / "x.json")]) == 3
    assert "cannot compare" in capsys.readouterr().err


def test_the_compare_command_exits_three_for_a_bad_file(tmp_path: Path) -> None:
    ok = _write(tmp_path / "a.json", [ProbeScore("a.One", 1, 0, NONE, 0)])
    bad = tmp_path / "bad.json"
    bad.write_text("nope", encoding="utf-8")
    assert main(["compare", "--before", ok, "--after", str(bad)]) == 3
