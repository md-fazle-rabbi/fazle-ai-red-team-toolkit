"""Tests for the run summary."""

import json

import pytest
from pydantic import ValidationError

from redteam_toolkit.scoring import Attempt, ProbeScore, score_attempts
from redteam_toolkit.summary import (
    SCHEMA_VERSION,
    ProbeSummary,
    summarize,
    summary_json,
)

BOTH = {"canary_leak": 1, "pii_exposed": 1}
NONE = {"canary_leak": 0, "pii_exposed": 0}


def test_an_attempt_flagged_by_two_detectors_counts_once() -> None:
    attempts = [Attempt("a.One", ("SECRET-1 mail a@b.co",)), Attempt("a.One", ("ok",))]
    (score,) = score_attempts(attempts, canaries=["SECRET-1"])
    assert score.failures == BOTH
    assert score.flagged == 1
    assert score.evaluated == 2


def test_totals_and_rates_are_computed_from_the_probe_scores() -> None:
    summary = summarize(
        [
            ProbeScore("a.One", 8, 2, NONE, 0),
            ProbeScore("b.Two", 8, 0, BOTH, 1),
        ]
    )
    assert summary.schema_version == SCHEMA_VERSION
    assert (summary.evaluated, summary.skipped, summary.flagged) == (16, 2, 1)
    assert summary.flagged_rate == 0.0625
    assert [p.flagged_rate for p in summary.probes] == [0.0, 0.125]


def test_a_probe_with_nothing_evaluated_has_no_rate() -> None:
    summary = summarize([ProbeScore("a.One", 0, 4, NONE, 0)])
    assert summary.probes[0].flagged_rate is None
    assert summary.flagged_rate is None


def test_an_empty_run_has_no_rate() -> None:
    assert summarize([]).flagged_rate is None


def test_the_json_has_the_expected_keys_and_no_text_fields() -> None:
    data = json.loads(summary_json(summarize([ProbeScore("a.One", 1, 0, NONE, 0)])))
    assert set(data) == {
        "schema_version",
        "detectors",
        "evaluated",
        "skipped",
        "flagged",
        "flagged_rate",
        "probes",
    }
    assert set(data["probes"][0]) == {
        "probe",
        "evaluated",
        "skipped",
        "flagged",
        "failures",
        "flagged_rate",
    }


def test_unknown_fields_are_rejected() -> None:
    with pytest.raises(ValidationError):
        ProbeSummary.model_validate(
            {
                "probe": "a",
                "evaluated": 1,
                "skipped": 0,
                "flagged": 0,
                "failures": {},
                "flagged_rate": None,
                "prompt": "x",
            }
        )
