"""Tests for the report generator."""

import json
from datetime import UTC, datetime
from pathlib import Path

import pytest

from redteam_toolkit.cli import main
from redteam_toolkit.fairness import FairnessSummary, read_fairness_summary
from redteam_toolkit.report import (
    LIMITATIONS,
    ReportBuildError,
    RunInput,
    build_report,
    parse_run_spec,
)
from redteam_toolkit.roe import load_roe
from redteam_toolkit.scoring import ProbeScore
from redteam_toolkit.summary import CAVEAT, summarize, summary_json
from tests.roe_samples import VALID

NONE = {"canary_leak": 0, "pii_exposed": 0}
PII = {"canary_leak": 0, "pii_exposed": 1}
NOW = datetime(2026, 10, 23, 12, 0, tzinfo=UTC)


def _roe(tmp_path: Path) -> Path:
    path = tmp_path / "roe.toml"
    path.write_text(VALID, encoding="utf-8")
    return path


def _summary(tmp_path: Path, name: str, scores: list[ProbeScore]) -> Path:
    path = tmp_path / name
    path.write_text(summary_json(summarize(scores)), encoding="utf-8")
    return path


def _run(label: str, suite: str, scores: list[ProbeScore]) -> RunInput:
    return RunInput(label, suite, summarize(scores))


def test_the_report_has_every_section(tmp_path: Path) -> None:
    loaded = load_roe(_roe(tmp_path))
    run = _run("weak", "prompt_injection", [ProbeScore("a.One", 8, 2, PII, 1)])
    text = build_report(loaded, [run], generated_at=NOW)
    for heading in (
        "# Red team report: repo1-local-selftest",
        "## Overview",
        "## Engagement",
        "## Results",
        "### weak (prompt_injection)",
        "## Threat mapping",
        "## Limitations",
    ):
        assert heading in text
    assert "Generated 2026-10-23T12:00:00+00:00." in text
    assert f"Rules of Engagement file SHA-256: {loaded.sha256}" in text
    assert "| a.One | 8 | 2 | 1 | 12.5% |" in text
    assert "2 attempts had no answer" in text
    assert "canary_leak 0, pii_exposed 1" in text
    assert "LLM01 Prompt Injection" in text
    assert "AML.T0051 LLM Prompt Injection (Execution)" in text
    for item in LIMITATIONS:
        assert item in text


def test_a_suite_with_no_atlas_entry_says_none(tmp_path: Path) -> None:
    loaded = load_roe(_roe(tmp_path))
    run = _run("r", "pii_leakage", [ProbeScore("a.One", 4, 0, NONE, 0)])
    assert "AML.T0057" in build_report(loaded, [run], generated_at=NOW)


def test_a_pipe_in_a_probe_name_stays_in_its_cell(tmp_path: Path) -> None:
    loaded = load_roe(_roe(tmp_path))
    run = _run("r", "prompt_injection", [ProbeScore("a|b\nc", 4, 0, NONE, 0)])
    assert "| a\\|b c |" in build_report(loaded, [run], generated_at=NOW)


def test_two_labelled_runs_of_one_suite_are_both_listed(tmp_path: Path) -> None:
    loaded = load_roe(_roe(tmp_path))
    scores = [ProbeScore("a.One", 4, 0, NONE, 0)]
    runs = [
        _run("weak", "prompt_injection", scores),
        _run("hardened", "prompt_injection", scores),
    ]
    text = build_report(loaded, runs, generated_at=NOW)
    assert "### weak (prompt_injection)" in text
    assert "### hardened (prompt_injection)" in text
    assert text.count("### prompt_injection") == 1


def test_a_suite_outside_the_engagement_is_rejected(tmp_path: Path) -> None:
    loaded = load_roe(_roe(tmp_path))
    run = _run("r", "jailbreak", [ProbeScore("a.One", 4, 0, NONE, 0)])
    with pytest.raises(ReportBuildError, match="allowed_suites"):
        build_report(loaded, [run], generated_at=NOW)


def test_duplicate_label_and_suite_is_rejected(tmp_path: Path) -> None:
    loaded = load_roe(_roe(tmp_path))
    run = _run("r", "prompt_injection", [ProbeScore("a.One", 4, 0, NONE, 0)])
    with pytest.raises(ReportBuildError, match="share"):
        build_report(loaded, [run, run], generated_at=NOW)


def test_a_run_with_nothing_evaluated_is_rejected(tmp_path: Path) -> None:
    loaded = load_roe(_roe(tmp_path))
    run = _run("r", "prompt_injection", [ProbeScore("a.One", 0, 4, NONE, 0)])
    with pytest.raises(ReportBuildError, match="no evaluated"):
        build_report(loaded, [run], generated_at=NOW)


def test_no_runs_is_rejected(tmp_path: Path) -> None:
    with pytest.raises(ReportBuildError, match="no runs"):
        build_report(load_roe(_roe(tmp_path)), [], generated_at=NOW)


def test_a_signed_document_hash_is_shown(tmp_path: Path) -> None:
    digest = "a" * 64
    text = VALID.replace(
        'kind = "self_owned"', f'kind = "signed_document"\nsha256 = "{digest}"'
    )
    path = tmp_path / "signed.toml"
    path.write_text(text, encoding="utf-8")
    run = _run("r", "prompt_injection", [ProbeScore("a.One", 4, 0, NONE, 0)])
    out = build_report(load_roe(path), [run], generated_at=NOW)
    assert f"Signed document SHA-256: {digest}" in out


@pytest.mark.parametrize(
    ("spec", "expected"),
    [
        ("jailbreak=x.json", ("jailbreak", "run", "x.json")),
        ("jailbreak:After fix=x.json", ("jailbreak", "After fix", "x.json")),
        ("jailbreak=dir/a=b.json", ("jailbreak", "run", "dir/a=b.json")),
    ],
)
def test_run_specs_parse(spec: str, expected: tuple[str, str, str]) -> None:
    assert parse_run_spec(spec) == expected


@pytest.mark.parametrize(
    "spec",
    ["jailbreak", "jailbreak=", "nonsense=x.json", "jailbreak:#=x"],
)
def test_bad_run_specs_are_rejected(spec: str) -> None:
    with pytest.raises(ReportBuildError):
        parse_run_spec(spec)


def test_the_command_writes_the_report(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    summary = _summary(tmp_path, "s.json", [ProbeScore("a.One", 8, 0, PII, 1)])
    out = tmp_path / "report.md"
    code = main(
        [
            "report",
            "--file",
            str(_roe(tmp_path)),
            "--run",
            f"prompt_injection:weak={summary}",
            "--out",
            str(out),
        ]
    )
    assert code == 0
    assert "report written" in capsys.readouterr().out
    text = out.read_text(encoding="utf-8")
    assert "### weak (prompt_injection)" in text
    assert "12.5%" in text


def test_the_command_refuses_without_a_valid_roe_file(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    summary = _summary(tmp_path, "s.json", [ProbeScore("a.One", 8, 0, PII, 1)])
    out = tmp_path / "report.md"
    code = main(
        [
            "report",
            "--file",
            str(tmp_path / "missing.toml"),
            "--run",
            f"prompt_injection={summary}",
            "--out",
            str(out),
        ]
    )
    assert code == 2
    assert "refused" in capsys.readouterr().err
    assert not out.exists()


@pytest.mark.parametrize("case", ["missing", "empty_run", "bad_spec", "bad_out"])
def test_the_command_exits_3_when_it_cannot_report(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], case: str
) -> None:
    good = _summary(tmp_path, "s.json", [ProbeScore("a.One", 8, 0, PII, 1)])
    empty = _summary(tmp_path, "e.json", [ProbeScore("a.One", 0, 4, NONE, 0)])
    spec = {
        "missing": str(tmp_path / "nope.json"),
        "empty_run": str(empty),
        "bad_spec": str(good),
        "bad_out": str(good),
    }[case]
    out = tmp_path / "no-dir" / "r.md" if case == "bad_out" else tmp_path / "r.md"
    run = f"nonsense={spec}" if case == "bad_spec" else f"prompt_injection={spec}"
    code = main(
        ["report", "--file", str(_roe(tmp_path)), "--run", run, "--out", str(out)]
    )
    assert code == 3
    assert "cannot report" in capsys.readouterr().err
    assert not out.exists()


WITH_BIAS = VALID.replace(
    'allowed_suites = ["prompt_injection", "pii_leakage"]',
    'allowed_suites = ["prompt_injection", "pii_leakage", "bias"]',
)
EXAMPLE = (
    Path(__file__).resolve().parents[1]
    / "examples"
    / ("fairness.synthetic-example.json")
)


def _bias_roe(tmp_path: Path) -> Path:
    path = tmp_path / "roe-bias.toml"
    path.write_text(WITH_BIAS, encoding="utf-8")
    return path


def _fairness(tmp_path: Path, *, gap: float = 0.0, count: int = 100) -> Path:
    groups = [
        {
            "group": name,
            "count": count,
            "selection_rate": 0.5 + shift,
            "true_positive_rate": 0.8,
            "false_positive_rate": 0.1,
        }
        for name, shift in (("a", 0.0), ("b", gap))
    ]
    body = {
        "schema_version": 1,
        "attribute": "group",
        "data": "synthetic",
        "groups": groups,
    }
    path = tmp_path / "fairness.json"
    path.write_text(json.dumps(body), encoding="utf-8")
    return path


def _summary_of(path: Path) -> FairnessSummary:
    return read_fairness_summary(path)


def test_a_fairness_section_shows_the_groups_and_the_result(tmp_path: Path) -> None:
    loaded = load_roe(_bias_roe(tmp_path))
    text = build_report(
        loaded, [], generated_at=NOW, fairness=read_fairness_summary(EXAMPLE)
    )
    assert "### Group fairness (bias)" in text
    assert "| group_a | 200 | 0.5000 | 0.8000 | 0.1000 |" in text
    assert "Demographic parity difference: 0.0400 (limit 0.1)." in text
    assert "Result: both differences are within their limits." in text
    assert "A group fairness summary over 2 groups is included." in text
    assert "LLM09 Misinformation" in text
    assert "synthetic data and a stand-in model" in text
    assert "attempts were evaluated" not in text
    assert CAVEAT not in text


def test_a_fairness_gap_is_reported_as_a_result(tmp_path: Path) -> None:
    loaded = load_roe(_bias_roe(tmp_path))
    summary = _summary_of(_fairness(tmp_path, gap=0.3))
    text = build_report(loaded, [], generated_at=NOW, fairness=summary)
    assert "Result: demographic parity difference 0.3000 is above 0.1." in text


def test_runs_and_fairness_can_be_reported_together(tmp_path: Path) -> None:
    loaded = load_roe(_bias_roe(tmp_path))
    run = _run("r", "prompt_injection", [ProbeScore("a.One", 4, 0, NONE, 0)])
    text = build_report(
        loaded, [run], generated_at=NOW, fairness=_summary_of(_fairness(tmp_path))
    )
    assert "4 attempts were evaluated." in text
    assert "### prompt_injection" in text
    assert text.count("### bias") == 1


def test_fairness_needs_the_bias_suite_in_the_engagement(tmp_path: Path) -> None:
    loaded = load_roe(_roe(tmp_path))
    summary = _summary_of(_fairness(tmp_path))
    with pytest.raises(ReportBuildError, match="'bias' is not in allowed_suites"):
        build_report(loaded, [], generated_at=NOW, fairness=summary)


def test_a_fairness_summary_that_cannot_be_judged_is_rejected(tmp_path: Path) -> None:
    loaded = load_roe(_bias_roe(tmp_path))
    summary = _summary_of(_fairness(tmp_path, count=5))
    with pytest.raises(ReportBuildError, match="cannot be judged"):
        build_report(loaded, [], generated_at=NOW, fairness=summary)


def test_a_missing_error_rate_shows_as_na(tmp_path: Path) -> None:
    body = json.loads(_fairness(tmp_path).read_text(encoding="utf-8"))
    body["groups"].append({"group": "c", "count": 100, "selection_rate": 0.5})
    path = tmp_path / "three.json"
    path.write_text(json.dumps(body), encoding="utf-8")
    loaded = load_roe(_bias_roe(tmp_path))
    text = build_report(loaded, [], generated_at=NOW, fairness=_summary_of(path))
    assert "| c | 100 | 0.5000 | n/a | n/a |" in text


def test_the_command_reports_fairness_alone(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    out = tmp_path / "report.md"
    code = main(
        [
            "report",
            "--file",
            str(_bias_roe(tmp_path)),
            "--fairness",
            str(_fairness(tmp_path)),
            "--out",
            str(out),
        ]
    )
    assert code == 0
    assert "report written" in capsys.readouterr().out
    assert "### Group fairness (bias)" in out.read_text(encoding="utf-8")


def test_the_command_needs_a_run_or_a_fairness_summary(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    out = tmp_path / "report.md"
    code = main(["report", "--file", str(_roe(tmp_path)), "--out", str(out)])
    assert code == 3
    assert "no runs" in capsys.readouterr().err
    assert not out.exists()


def test_the_command_exits_3_for_an_unreadable_fairness_summary(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    out = tmp_path / "report.md"
    code = main(
        [
            "report",
            "--file",
            str(_bias_roe(tmp_path)),
            "--fairness",
            str(tmp_path / "nope.json"),
            "--out",
            str(out),
        ]
    )
    assert code == 3
    assert "cannot report" in capsys.readouterr().err
    assert not out.exists()


def test_a_bias_run_and_a_fairness_summary_share_one_mapping_entry(
    tmp_path: Path,
) -> None:
    loaded = load_roe(_bias_roe(tmp_path))
    run = _run("r", "bias", [ProbeScore("a.One", 4, 0, NONE, 0)])
    text = build_report(
        loaded, [run], generated_at=NOW, fairness=_summary_of(_fairness(tmp_path))
    )
    assert text.count("### bias\n") == 1
    assert CAVEAT in text
