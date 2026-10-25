"""The findings catalogue holds only checked entries and honest wording."""

import pytest

from redteam_toolkit.findings import (
    FINDING_TEMPLATES,
    SCORING_ASSUMPTION,
    FindingTemplate,
    template_for,
)
from redteam_toolkit.roe import SUITES
from redteam_toolkit.threat_map import mapping_for

GOOD_VECTOR = "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N"
STEPS = ("one", "two")
BANNED = (
    "guaranteed",
    "unhackable",
    "100% compliant",
    "certified",
    chr(0x2014),
    chr(0x2013),
)


def _make(**changes: object) -> FindingTemplate:
    fields: dict[str, object] = {
        "id": "sample_finding",
        "title": "A title",
        "suite": "prompt_injection",
        "impact": "Some impact.",
        "remediation": STEPS,
        "vector": GOOD_VECTOR,
    }
    fields.update(changes)
    return FindingTemplate(**fields)  # type: ignore[arg-type]


def test_ids_are_unique() -> None:
    ids = [template.id for template in FINDING_TEMPLATES]
    assert len(ids) == len(set(ids))


def test_every_suite_a_template_names_is_mapped_in_the_threat_map() -> None:
    for template in FINDING_TEMPLATES:
        assert template.suite in SUITES
        assert mapping_for(template.suite).suite == template.suite


def test_the_scored_findings_have_the_expected_scores() -> None:
    scores = {
        template.id: template.cvss().base_score  # type: ignore[union-attr]
        for template in FINDING_TEMPLATES
        if template.vector is not None
    }
    assert scores == {
        "system_prompt_leak": 6.5,
        "personal_data_exposed": 6.5,
        "injection_accepted": 5.4,
        "image_injection_accepted": 5.4,
    }


def test_the_unscored_findings_say_why() -> None:
    unscored = [t for t in FINDING_TEMPLATES if t.vector is None]
    assert {t.suite for t in unscored} == {"bias", "adversarial_ml", "load"}
    for template in unscored:
        assert template.cvss() is None
        assert template.not_scored_reason


def test_every_template_has_impact_and_steps() -> None:
    for template in FINDING_TEMPLATES:
        assert template.title
        assert template.impact
        assert len(template.remediation) >= 2


def test_the_wording_avoids_overclaims_and_dashes() -> None:
    for template in FINDING_TEMPLATES:
        text = " ".join(
            (
                template.title,
                template.impact,
                template.not_scored_reason,
                *template.remediation,
            )
        )
        for banned in BANNED:
            assert banned not in text.lower()
    assert "judgement" in SCORING_ASSUMPTION


def test_template_for_finds_one_and_refuses_an_unknown_id() -> None:
    assert template_for("injection_accepted").suite == "prompt_injection"
    with pytest.raises(KeyError, match="no finding template"):
        template_for("nothing_here")


def test_a_scored_template_gives_its_cvss_result() -> None:
    result = _make().cvss()
    assert result is not None
    assert result.base_score == 5.4
    assert result.severity == "Medium"


@pytest.mark.parametrize(
    ("changes", "message"),
    [
        ({"id": "Bad Id"}, "not a valid finding id"),
        ({"suite": "no_such_suite"}, "not a known suite"),
        ({"vector": None}, "exactly one of"),
        ({"not_scored_reason": "because"}, "exactly one of"),
        ({"remediation": ("only one",)}, "at least two"),
        ({"vector": "CVSS:3.1/AV:N"}, "not a base metric|exactly"),
    ],
)
def test_a_bad_template_is_refused(changes: dict[str, object], message: str) -> None:
    with pytest.raises(ValueError, match=message):
        _make(**changes)
