"""The Agentic Top 10 part of the threat map."""

import re
from datetime import UTC, datetime
from pathlib import Path

from redteam_toolkit.image_run import SCHEMA_VERSION, ImageRunSummary
from redteam_toolkit.report import build_report
from redteam_toolkit.roe import load_roe
from redteam_toolkit.threat_map import (
    OWASP_AGENTIC,
    SUITE_MAPPINGS,
    agentic_lines,
    mapping_for,
)

EXAMPLES = Path(__file__).resolve().parents[1] / "examples"


def test_the_agentic_list_has_ten_well_formed_entries() -> None:
    assert list(OWASP_AGENTIC) == [f"ASI{n:02d}" for n in range(1, 11)]
    for aid, name in OWASP_AGENTIC.items():
        assert re.fullmatch(r"ASI\d{2}", aid)
        assert name


def test_every_mapped_agentic_id_is_in_the_list() -> None:
    for entry in SUITE_MAPPINGS:
        assert set(entry.asi) <= set(OWASP_AGENTIC), entry.suite


def test_the_text_and_image_injection_suites_map_to_goal_hijack() -> None:
    assert mapping_for("prompt_injection").asi == ("ASI01",)
    assert mapping_for("image_prompt_injection").asi == ("ASI01",)
    assert (
        "Agentic list does not name images"
        in mapping_for("image_prompt_injection").note
    )


def test_a_suite_without_an_agentic_entry_has_no_line() -> None:
    assert mapping_for("load").asi == ()
    assert agentic_lines(mapping_for("load")) == []


def test_the_line_names_each_entry_and_the_fit_caveat() -> None:
    (line,) = agentic_lines(mapping_for("rogue_agent"))
    assert "ASI02 Tool Misuse and Exploitation" in line
    assert "ASI10 Rogue Agents" in line
    assert "closest fit, in full only for an agent target" in line


def test_the_report_prints_the_agentic_line() -> None:
    summary = ImageRunSummary(
        schema_version=SCHEMA_VERSION,
        sent=20,
        accepted=0,
        blocked=20,
        errored=0,
        status_codes={"400": 20},
    )
    text = build_report(
        load_roe(EXAMPLES / "roe.stub-image.toml"),
        [],
        generated_at=datetime(2026, 10, 25, 12, 0, tzinfo=UTC),
        image=summary,
    )
    assert "- OWASP Agentic 2026 (closest fit" in text
    assert "ASI01 Agent Goal Hijack" in text
