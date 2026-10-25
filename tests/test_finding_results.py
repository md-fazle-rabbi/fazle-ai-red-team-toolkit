"""Which findings a set of results supports, and what the evidence says."""

from redteam_toolkit.exploit_run import EntryOutcome, ExploitRunSummary
from redteam_toolkit.fairness import FairnessSummary
from redteam_toolkit.finding_results import Finding, collect_findings
from redteam_toolkit.image_run import SCHEMA_VERSION, ImageRunSummary
from redteam_toolkit.robustness import RobustnessSummary
from redteam_toolkit.scoring import ProbeScore
from redteam_toolkit.summary import RunSummary, summarize

NONE = {"canary_leak": 0, "pii_exposed": 0}
CANARY = {"canary_leak": 3, "pii_exposed": 0}
PII = {"canary_leak": 0, "pii_exposed": 2}
BOTH = {"canary_leak": 1, "pii_exposed": 1}


def _run(failures: dict[str, int], label: str = "weak") -> tuple[str, str, RunSummary]:
    flagged = 1 if any(failures.values()) else 0
    score = ProbeScore("a.One", 8, 0, failures, flagged)
    return (label, "prompt_injection", summarize([score]))


def _exploit(
    *bypassed: tuple[str, tuple[str, ...]], held: int = 3
) -> ExploitRunSummary:
    entries = [
        EntryOutcome.model_validate(
            {
                "id": f"EX-{number:03d}",
                "category": "injection_variant",
                "suite": "prompt_injection",
                "owasp": list(owasp),
                "asi": [],
                "outcome": "bypassed",
            }
        )
        for number, (_, owasp) in enumerate(bypassed, start=1)
    ]
    entries += [
        EntryOutcome.model_validate(
            {
                "id": f"EX-{number:03d}",
                "category": "injection_variant",
                "suite": "prompt_injection",
                "owasp": ["LLM01"],
                "asi": [],
                "outcome": "held",
            }
        )
        for number in range(len(bypassed) + 1, len(bypassed) + held + 1)
    ]
    return ExploitRunSummary(
        schema_version=1,
        sent=len(entries),
        blocked=0,
        held=held,
        bypassed=len(bypassed),
        errored=0,
        canaries_checked=1,
        entries=tuple(entries),
    )


def _image(accepted: int) -> ImageRunSummary:
    return ImageRunSummary(
        schema_version=SCHEMA_VERSION,
        sent=20,
        accepted=accepted,
        blocked=20 - accepted,
        errored=0,
        status_codes={
            code: n for code, n in (("201", accepted), ("400", 20 - accepted)) if n
        },
    )


def _fairness(gap: float) -> FairnessSummary:
    groups = [
        {
            "group": name,
            "count": 100,
            "selection_rate": 0.5 + shift,
            "true_positive_rate": 0.8,
            "false_positive_rate": 0.1,
        }
        for name, shift in (("a", 0.0), ("b", gap))
    ]
    return FairnessSummary.model_validate(
        {
            "schema_version": 1,
            "attribute": "group",
            "data": "synthetic",
            "groups": groups,
        }
    )


def _robustness(drop: float) -> RobustnessSummary:
    return RobustnessSummary.model_validate(
        {
            "schema_version": 1,
            "data": "synthetic",
            "model": "toy_model",
            "attack": "fast_gradient_method",
            "rows": 2000,
            "clean_accuracy": 0.9,
            "points": [{"epsilon": 0.1, "accuracy": round(0.9 - drop, 6)}],
        }
    )


def _collect(
    *,
    runs: list[tuple[str, str, RunSummary]] | None = None,
    fairness: FairnessSummary | None = None,
    robustness: RobustnessSummary | None = None,
    image: ImageRunSummary | None = None,
    exploit: ExploitRunSummary | None = None,
) -> tuple[Finding, ...]:
    return collect_findings(
        runs=runs or [],
        fairness=fairness,
        robustness=robustness,
        image=image,
        exploit=exploit,
    )


def _ids(findings: tuple[Finding, ...]) -> list[str]:
    return [finding.template.id for finding in findings]


def test_results_that_show_nothing_give_no_findings() -> None:
    assert (
        _collect(
            runs=[_run(NONE)],
            fairness=_fairness(0.0),
            robustness=_robustness(0.05),
            image=_image(0),
            exploit=_exploit(),
        )
        == ()
    )


def test_no_inputs_give_no_findings() -> None:
    assert _collect() == ()


def test_a_canary_hit_gives_the_system_prompt_finding_with_a_count() -> None:
    (finding,) = _collect(runs=[_run(CANARY, label="garak-weak")])
    assert finding.template.id == "system_prompt_leak"
    assert finding.evidence == (
        "run garak-weak (prompt_injection): 3 attempts leaked the canary",
    )


def test_a_personal_data_hit_gives_the_personal_data_finding() -> None:
    (finding,) = _collect(runs=[_run(PII)])
    assert finding.template.id == "personal_data_exposed"
    assert "2 attempts exposed personal data" in finding.evidence[0]


def test_one_run_can_give_both_findings() -> None:
    assert set(_ids(_collect(runs=[_run(BOTH)]))) == {
        "system_prompt_leak",
        "personal_data_exposed",
    }


def test_an_exploit_bypass_is_filed_by_its_owasp_tags() -> None:
    exploit = _exploit(
        ("a", ("LLM01",)),
        ("b", ("LLM01", "LLM07")),
        ("c", ("LLM02",)),
        ("d", ("LLM01",)),
    )
    findings = {f.template.id: f for f in _collect(exploit=exploit)}
    assert set(findings) == {
        "injection_accepted",
        "system_prompt_leak",
        "personal_data_exposed",
    }
    assert findings["injection_accepted"].evidence == (
        "exploit library: EX-001, EX-004 bypassed (2 of 7 probes)",
    )
    assert findings["system_prompt_leak"].evidence == (
        "exploit library: EX-002 bypassed (1 of 7 probes)",
    )


def test_an_exploit_run_with_only_held_probes_gives_nothing() -> None:
    assert _collect(exploit=_exploit(held=5)) == ()


def test_evidence_from_two_sources_is_merged_under_one_finding() -> None:
    findings = _collect(runs=[_run(CANARY)], exploit=_exploit(("a", ("LLM07",))))
    assert _ids(findings) == ["system_prompt_leak"]
    assert len(findings[0].evidence) == 2


def test_an_accepted_image_gives_the_image_finding() -> None:
    (finding,) = _collect(image=_image(2))
    assert finding.template.id == "image_injection_accepted"
    assert finding.evidence == ("image run: 2 of 20 uploads accepted",)


def test_a_failing_fairness_summary_gives_the_gap_finding() -> None:
    (finding,) = _collect(fairness=_fairness(0.3))
    assert finding.template.id == "group_outcome_gap"
    assert "parity" in finding.evidence[0]


def test_a_failing_robustness_summary_gives_the_drop_finding() -> None:
    (finding,) = _collect(robustness=_robustness(0.3))
    assert finding.template.id == "evasion_accuracy_drop"
    assert "accuracy drop" in finding.evidence[0]


def test_findings_are_sorted_by_score_with_unscored_last() -> None:
    findings = _collect(
        runs=[_run(PII)],
        exploit=_exploit(("a", ("LLM01",))),
        fairness=_fairness(0.3),
        image=_image(1),
    )
    assert _ids(findings) == [
        "personal_data_exposed",
        "image_injection_accepted",
        "injection_accepted",
        "group_outcome_gap",
    ]
