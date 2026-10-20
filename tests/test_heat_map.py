"""Checks the heat map renders correctly and the committed copy is current."""

from pathlib import Path
from xml.etree import ElementTree

from redteam_toolkit.heat_map import STRIDE_LABELS, render_heat_map_svg
from redteam_toolkit.threat_map import OWASP_LLM, STRIDE_CATEGORIES

SVG_NS = "{http://www.w3.org/2000/svg}"
COMMITTED = Path(__file__).resolve().parent.parent / "docs" / "threat-map.svg"


def _cells() -> dict[tuple[str, str], int]:
    # Why: the svg is our own output, never untrusted input.
    root = ElementTree.fromstring(render_heat_map_svg())  # noqa: S314
    return {
        (r.attrib["data-stride"], r.attrib["data-owasp"]): int(r.attrib["data-count"])
        for r in root.iter(f"{SVG_NS}rect")
        if "data-stride" in r.attrib
    }


def test_output_is_well_formed_xml_with_the_svg_namespace() -> None:
    root = ElementTree.fromstring(render_heat_map_svg())  # noqa: S314
    assert root.tag == f"{SVG_NS}svg"
    assert root.attrib["role"] == "img"


def test_there_is_one_cell_for_every_stride_and_owasp_pair() -> None:
    cells = _cells()
    assert len(cells) == len(STRIDE_CATEGORIES) * len(OWASP_LLM)


def test_a_known_cell_shows_its_count_and_an_empty_cell_shows_zero() -> None:
    cells = _cells()
    assert cells[("elevation_of_privilege", "LLM01")] == 3
    assert cells[("spoofing", "LLM01")] == 0


def test_every_label_and_the_honesty_notes_are_present() -> None:
    svg = render_heat_map_svg()
    for label in STRIDE_LABELS.values():
        assert label in svg
    for owasp_id, name in OWASP_LLM.items():
        assert owasp_id in svg
        assert name in svg
    assert "not drawn here" in svg
    assert "not that the pair is safe" in svg


def test_every_stride_category_has_a_label() -> None:
    assert set(STRIDE_LABELS) == set(STRIDE_CATEGORIES)


def test_rendering_twice_gives_identical_output() -> None:
    assert render_heat_map_svg() == render_heat_map_svg()


def test_the_committed_svg_matches_what_the_code_draws() -> None:
    assert COMMITTED.read_text() == render_heat_map_svg()
