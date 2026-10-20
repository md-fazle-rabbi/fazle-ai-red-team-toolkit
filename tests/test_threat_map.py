"""Checks the threat map stays complete and well formed."""

import re

import pytest

from redteam_toolkit.roe import SUITES
from redteam_toolkit.threat_map import (
    ATLAS_TECHNIQUES,
    OWASP_LLM,
    STRIDE_CATEGORIES,
    SUITE_MAPPINGS,
    heat_map_counts,
    mapping_for,
)


def test_every_suite_the_gate_allows_has_exactly_one_mapping() -> None:
    mapped = [m.suite for m in SUITE_MAPPINGS]
    assert sorted(mapped) == sorted(SUITES)
    assert len(mapped) == len(set(mapped))


def test_every_suite_has_a_stride_category_and_an_owasp_id() -> None:
    for m in SUITE_MAPPINGS:
        assert m.stride, m.suite
        assert m.owasp, m.suite


def test_stride_values_are_known() -> None:
    for m in SUITE_MAPPINGS:
        assert set(m.stride) <= set(STRIDE_CATEGORIES)


def test_every_atlas_id_is_well_formed_and_has_a_recorded_name() -> None:
    pattern = re.compile(r"^AML\.T\d{4}(\.\d{3})?$")
    for m in SUITE_MAPPINGS:
        for tid in m.atlas:
            assert pattern.match(tid), tid
            assert tid in ATLAS_TECHNIQUES, tid
    for name, tactics in ATLAS_TECHNIQUES.values():
        assert name
        assert tactics


def test_every_owasp_id_is_in_the_2025_list() -> None:
    assert len(OWASP_LLM) == 10
    for m in SUITE_MAPPINGS:
        assert set(m.owasp) <= set(OWASP_LLM)


def test_no_unused_atlas_entries() -> None:
    used = {tid for m in SUITE_MAPPINGS for tid in m.atlas}
    assert used == set(ATLAS_TECHNIQUES)


def test_a_gap_is_stated_where_a_suite_has_no_atlas_technique() -> None:
    for m in SUITE_MAPPINGS:
        if not m.atlas:
            assert m.note


def test_mapping_for_finds_a_suite_and_rejects_an_unknown_one() -> None:
    assert mapping_for("load").owasp == ("LLM10",)
    with pytest.raises(KeyError):
        mapping_for("no_such_suite")


def test_heat_map_counts_add_up() -> None:
    counts = heat_map_counts()
    expected = sum(len(m.stride) * len(m.owasp) for m in SUITE_MAPPINGS)
    assert sum(counts.values()) == expected
    assert counts[("elevation_of_privilege", "LLM01")] == 3
