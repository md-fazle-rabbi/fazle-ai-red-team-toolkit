"""The report's findings section."""

from datetime import UTC, datetime
from pathlib import Path

from redteam_toolkit.fairness import FairnessSummary
from redteam_toolkit.findings import SCORING_ASSUMPTION, template_for
from redteam_toolkit.report import RunInput, build_report
from redteam_toolkit.roe import load_roe
from redteam_toolkit.scoring import ProbeScore
from redteam_toolkit.summary import summarize
from tests.roe_samples import VALID

NOW = datetime(2026, 10, 25, 12, 0, tzinfo=UTC)
NONE = {"canary_leak": 0, "pii_exposed": 0}
PII = {"canary_leak": 0, "pii_exposed": 2}
WITH_BIAS = VALID.replace(
    'allowed_suites = ["prompt_injection", "pii_leakage"]',
    'allowed_suites = ["prompt_injection", "pii_leakage", "bias"]',
)


def _roe(tmp_path: Path, text: str = VALID) -> Path:
    path = tmp_path / "roe.toml"
    path.write_text(text, encoding="utf-8")
    return path


def _run(failures: dict[str, int]) -> RunInput:
    flagged = 1 if any(failures.values()) else 0
    score = ProbeScore("a.One", 8, 0, failures, flagged)
    return RunInput("weak", "pii_leakage", summarize([score]))


def test_a_run_with_no_hits_says_no_finding_and_does_not_claim_safety(
    tmp_path: Path,
) -> None:
    loaded = load_roe(_roe(tmp_path))
    text = build_report(loaded, [_run(NONE)], generated_at=NOW)
    assert "## Findings" in text
    assert "No finding met its threshold in the results given." in text
    assert "does not show the target has no weakness" in text
    assert "### F1" not in text


def test_a_finding_shows_its_score_vector_evidence_impact_and_steps(
    tmp_path: Path,
) -> None:
    loaded = load_roe(_roe(tmp_path))
    text = build_report(loaded, [_run(PII)], generated_at=NOW)
    template = template_for("personal_data_exposed")
    assert "1 finding(s) met their threshold" in text
    assert SCORING_ASSUMPTION in text
    assert "| F1 | Personal data appears in answers | Medium | 6.5 |" in text
    assert "### F1: Personal data appears in answers" in text
    assert (
        "- Severity: Medium, CVSS v3.1 base 6.5 "
        "(CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N)"
    ) in text
    assert "OWASP LLM: LLM02 Sensitive Information Disclosure" in text
    assert "  - run weak (pii_leakage): 2 attempts exposed personal data" in text
    assert f"- Business impact: {template.impact}" in text
    assert f"  1. {template.remediation[0]}" in text


def test_an_unscored_finding_says_it_is_not_scored_and_why(tmp_path: Path) -> None:
    loaded = load_roe(_roe(tmp_path, WITH_BIAS))
    fairness = FairnessSummary.model_validate(
        {
            "schema_version": 1,
            "attribute": "group",
            "data": "synthetic",
            "groups": [
                {
                    "group": name,
                    "count": 100,
                    "selection_rate": rate,
                    "true_positive_rate": 0.8,
                    "false_positive_rate": 0.1,
                }
                for name, rate in (("a", 0.5), ("b", 0.8))
            ],
        }
    )
    text = build_report(loaded, [], generated_at=NOW, fairness=fairness)
    template = template_for("group_outcome_gap")
    assert "| F1 | " + template.title + " | not scored | n/a |" in text
    assert f"- Severity: not scored. {template.not_scored_reason}" in text


def test_the_findings_come_after_the_results_and_before_the_mapping(
    tmp_path: Path,
) -> None:
    loaded = load_roe(_roe(tmp_path))
    text = build_report(loaded, [_run(PII)], generated_at=NOW)
    assert (
        text.index("## Results")
        < text.index("## Findings")
        < text.index("## Threat mapping")
    )
