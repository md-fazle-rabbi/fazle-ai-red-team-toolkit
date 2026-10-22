"""Tests for the load gate. The stats files here only imitate Locust's format."""

from pathlib import Path

import pytest

from redteam_toolkit.cli import main
from redteam_toolkit.load_gate import (
    LoadGateError,
    LoadStats,
    evaluate,
    read_locust_stats,
)

HEADER = "Type,Name,Request Count,Failure Count,Requests/s,95%"


def _stats(
    tmp_path: Path,
    *,
    requests: str = "2000",
    failures: str = "0",
    rate: str = "130.5",
    p95: str = "480",
    header: str = HEADER,
    name: str = "Aggregated",
) -> Path:
    path = tmp_path / "out_stats.csv"
    path.write_text(
        f"{header}\nPOST,/query,{requests},{failures},{rate},{p95}\n"
        f",{name},{requests},{failures},{rate},{p95}\n",
        encoding="utf-8",
    )
    return path


def test_the_aggregated_row_is_read(tmp_path: Path) -> None:
    assert read_locust_stats(_stats(tmp_path)) == LoadStats(2000, 0, 480.0, 130.5)


def test_a_file_without_an_aggregated_row_is_refused(tmp_path: Path) -> None:
    with pytest.raises(LoadGateError, match="Aggregated"):
        read_locust_stats(_stats(tmp_path, name="/other"))


def test_a_column_that_is_not_a_number_is_refused(tmp_path: Path) -> None:
    with pytest.raises(LoadGateError, match="N/A"):
        read_locust_stats(_stats(tmp_path, p95="N/A"))


def test_a_missing_column_is_refused(tmp_path: Path) -> None:
    header = "Type,Name,Request Count,Failure Count,Requests/s"
    path = tmp_path / "out_stats.csv"
    path.write_text(f"{header}\n,Aggregated,10,0,5\n", encoding="utf-8")
    with pytest.raises(LoadGateError, match="95%"):
        read_locust_stats(path)


def test_a_run_inside_both_thresholds_passes() -> None:
    result = evaluate(LoadStats(2000, 10, 480.0, 130.0))
    assert result.passed
    assert result.reasons == ()


def test_the_thresholds_themselves_still_pass() -> None:
    assert evaluate(LoadStats(1000, 10, 2000.0, 1.0)).passed


def test_a_slow_p95_fails() -> None:
    result = evaluate(LoadStats(2000, 0, 2000.1, 1.0))
    assert not result.passed
    assert "p95" in result.reasons[0]


def test_too_many_failures_fail() -> None:
    result = evaluate(LoadStats(1000, 11, 100.0, 1.0))
    assert not result.passed
    assert "failure rate" in result.reasons[0]
    assert "11 of 1000" in result.reasons[0]


def test_both_breaches_are_reported() -> None:
    result = evaluate(LoadStats(1000, 500, 9000.0, 1.0))
    assert len(result.reasons) == 2


def test_custom_thresholds_are_honored() -> None:
    stats = LoadStats(1000, 0, 480.0, 1.0)
    assert not evaluate(stats, max_p95_ms=400.0).passed
    assert evaluate(stats, max_p95_ms=500.0).passed


def test_a_run_with_too_few_requests_cannot_be_judged() -> None:
    with pytest.raises(LoadGateError, match="fewer than"):
        evaluate(LoadStats(99, 0, 1.0, 1.0))
    assert evaluate(LoadStats(5, 0, 1.0, 1.0), min_requests=5).passed


def test_the_command_passes_a_good_run(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    assert main(["load-gate", "--stats", str(_stats(tmp_path))]) == 0
    out = capsys.readouterr().out
    assert "load gate: pass" in out
    assert "p95_ms=480" in out


def test_the_command_fails_a_slow_run(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    assert main(["load-gate", "--stats", str(_stats(tmp_path, p95="2500"))]) == 1
    assert "load gate: fail" in capsys.readouterr().out


def test_the_command_takes_thresholds_from_options(tmp_path: Path) -> None:
    path = str(_stats(tmp_path))
    assert main(["load-gate", "--stats", path, "--max-p95-ms", "100"]) == 1
    assert main(["load-gate", "--stats", path, "--max-failure-rate", "0.5"]) == 0
    assert main(["load-gate", "--stats", path, "--min-requests", "5000"]) == 3


@pytest.mark.parametrize("requests", ["0", "10"])
def test_an_empty_or_tiny_run_exits_three(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], requests: str
) -> None:
    path = _stats(tmp_path, requests=requests)
    assert main(["load-gate", "--stats", str(path)]) == 3
    assert "cannot judge" in capsys.readouterr().err


def test_an_unreadable_file_exits_three(tmp_path: Path) -> None:
    assert main(["load-gate", "--stats", str(tmp_path / "nope.csv")]) == 3
    assert main(["load-gate", "--stats", str(_stats(tmp_path, p95="N/A"))]) == 3


@pytest.mark.parametrize(
    "option",
    [["--max-p95-ms", "0"], ["--max-p95-ms", "abc"], ["--max-failure-rate", "2"]],
)
def test_a_bad_threshold_is_refused(tmp_path: Path, option: list[str]) -> None:
    with pytest.raises(SystemExit):
        main(["load-gate", "--stats", str(_stats(tmp_path)), *option])
