"""The report's adversarial robustness section."""

import json
from datetime import UTC, datetime
from pathlib import Path

import pytest

from redteam_toolkit.cli import main
from redteam_toolkit.report import (
    ROBUSTNESS_LIMITATIONS,
    ReportBuildError,
    RunInput,
    build_report,
)
from redteam_toolkit.robustness import RobustnessSummary, read_robustness_summary
from redteam_toolkit.roe import load_roe
from redteam_toolkit.scoring import ProbeScore
from redteam_toolkit.summary import summarize
from tests.roe_samples import VALID

NOW = datetime(2026, 10, 23, 12, 0, tzinfo=UTC)
NONE = {"canary_leak": 0, "pii_exposed": 0}
EXAMPLE = (
    Path(__file__).resolve().parents[1]
    / "examples"
    / "robustness.synthetic-example.json"
)
WITH_ML = VALID.replace(
    'allowed_suites = ["prompt_injection", "pii_leakage"]',
    'allowed_suites = ["prompt_injection", "pii_leakage", "adversarial_ml"]',
)


def _roe(tmp_path: Path, text: str = WITH_ML) -> Path:
    path = tmp_path / "roe-ml.toml"
    path.write_text(text, encoding="utf-8")
    return path


def _robustness(
    tmp_path: Path,
    *,
    drop: float = 0.05,
    rows: int = 2000,
    epsilons: tuple[float, ...] = (0.05, 0.1, 0.3),
) -> Path:
    body = {
        "schema_version": 1,
        "data": "synthetic",
        "model": "toy_model",
        "attack": "fast_gradient_method",
        "rows": rows,
        "clean_accuracy": 0.9,
        "points": [
            {"epsilon": e, "accuracy": round(0.9 - drop * e / 0.1, 6)} for e in epsilons
        ],
    }
    path = tmp_path / "robustness.json"
    path.write_text(json.dumps(body), encoding="utf-8")
    return path


def _summary_of(path: Path) -> RobustnessSummary:
    return read_robustness_summary(path)


def test_a_robustness_section_shows_the_points_and_the_result(tmp_path: Path) -> None:
    loaded = load_roe(_roe(tmp_path))
    text = build_report(
        loaded, [], generated_at=NOW, robustness=read_robustness_summary(EXAMPLE)
    )
    assert "### Adversarial robustness (adversarial_ml)" in text
    assert "Model: " in text
    assert "| none (clean) | 0.9000 | 0.0000 |" in text
    assert "| 0.1 | 0.8400 | 0.0600 |" in text
    assert "Accuracy drop at epsilon 0.1: 0.0600 (limit 0.1)." in text
    assert "Result: the accuracy drop is within the limit." in text
    assert "A robustness summary over 3 perturbation sizes is included." in text
    assert "Suites covered: adversarial_ml." in text
    assert "## Threat mapping" in text
    assert "AML.T0043" in text
    for item in ROBUSTNESS_LIMITATIONS:
        assert f"- {item}" in text


def test_a_large_drop_is_reported_as_a_result(tmp_path: Path) -> None:
    loaded = load_roe(_roe(tmp_path))
    summary = _summary_of(_robustness(tmp_path, drop=0.2))
    text = build_report(loaded, [], generated_at=NOW, robustness=summary)
    assert "Result: accuracy drop 0.2000 at epsilon 0.1 is above 0.1." in text


def test_an_accuracy_gain_shows_as_a_plain_zero_or_negative_drop(
    tmp_path: Path,
) -> None:
    loaded = load_roe(_roe(tmp_path))
    summary = _summary_of(_robustness(tmp_path, drop=0.0))
    text = build_report(loaded, [], generated_at=NOW, robustness=summary)
    assert "| 0.05 | 0.9000 | 0.0000 |" in text
    assert "-0.0000" not in text


def test_runs_and_robustness_can_be_reported_together(tmp_path: Path) -> None:
    loaded = load_roe(_roe(tmp_path))
    scores = [ProbeScore("probe.a", 4, 0, NONE, 0)]
    run = RunInput("local", "prompt_injection", summarize(scores))
    text = build_report(
        loaded,
        [run],
        generated_at=NOW,
        robustness=_summary_of(_robustness(tmp_path)),
    )
    assert "### local (prompt_injection)" in text
    assert "### Adversarial robustness (adversarial_ml)" in text
    assert "Suites covered: prompt_injection, adversarial_ml." in text
    assert text.count("### adversarial_ml") == 1


def test_robustness_needs_the_adversarial_ml_suite_in_the_engagement(
    tmp_path: Path,
) -> None:
    loaded = load_roe(_roe(tmp_path, VALID))
    summary = _summary_of(_robustness(tmp_path))
    with pytest.raises(ReportBuildError, match="'adversarial_ml' is not in allowed"):
        build_report(loaded, [], generated_at=NOW, robustness=summary)


def test_a_summary_with_too_few_rows_is_rejected(tmp_path: Path) -> None:
    loaded = load_roe(_roe(tmp_path))
    summary = _summary_of(_robustness(tmp_path, rows=5))
    with pytest.raises(ReportBuildError, match="cannot be judged"):
        build_report(loaded, [], generated_at=NOW, robustness=summary)


def test_a_summary_without_the_judged_epsilon_is_rejected(tmp_path: Path) -> None:
    loaded = load_roe(_roe(tmp_path))
    summary = _summary_of(_robustness(tmp_path, epsilons=(0.05, 0.3)))
    with pytest.raises(ReportBuildError, match=r"no measurement at epsilon 0\.1"):
        build_report(loaded, [], generated_at=NOW, robustness=summary)


def test_the_command_reports_robustness_alone(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    out = tmp_path / "report.md"
    code = main(
        [
            "report",
            "--file",
            str(_roe(tmp_path)),
            "--robustness",
            str(_robustness(tmp_path)),
            "--out",
            str(out),
        ]
    )
    assert code == 0
    assert "report written" in capsys.readouterr().out
    assert "### Adversarial robustness" in out.read_text(encoding="utf-8")


def test_the_command_exits_3_for_an_unreadable_robustness_summary(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    out = tmp_path / "report.md"
    code = main(
        [
            "report",
            "--file",
            str(_roe(tmp_path)),
            "--robustness",
            str(tmp_path / "nope.json"),
            "--out",
            str(out),
        ]
    )
    assert code == 3
    assert "cannot report" in capsys.readouterr().err
    assert not out.exists()


def test_the_command_exits_3_for_a_robustness_summary_it_cannot_read_as_valid(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    bad = tmp_path / "bad.json"
    bad.write_text("{}", encoding="utf-8")
    out = tmp_path / "report.md"
    code = main(
        [
            "report",
            "--file",
            str(_roe(tmp_path)),
            "--robustness",
            str(bad),
            "--out",
            str(out),
        ]
    )
    assert code == 3
    assert "not a valid robustness summary" in capsys.readouterr().err


def test_the_ml_example_engagement_works_with_the_robustness_example() -> None:
    examples = EXAMPLE.parent
    text = build_report(
        load_roe(examples / "roe.stub-ml.toml"),
        [],
        generated_at=NOW,
        robustness=read_robustness_summary(EXAMPLE),
    )
    assert "# Red team report: stub-ml-selftest" in text
    assert "### Adversarial robustness (adversarial_ml)" in text
