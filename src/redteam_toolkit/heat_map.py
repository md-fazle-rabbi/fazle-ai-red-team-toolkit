"""Draws the threat map as an SVG grid: STRIDE categories by OWASP LLM entries.

Each cell shows how many suites map to that pair. The output depends only on
the data in threat_map.py, so the same data always gives the same bytes. That
lets a test fail when the committed picture is out of date.
"""

from __future__ import annotations

from typing import Final
from xml.sax.saxutils import escape

from redteam_toolkit.threat_map import (
    ATLAS_RELEASE,
    OWASP_LLM,
    OWASP_LLM_EDITION,
    STRIDE_CATEGORIES,
    heat_map_counts,
)

STRIDE_LABELS: Final[dict[str, str]] = {
    "spoofing": "Spoofing",
    "tampering": "Tampering",
    "repudiation": "Repudiation",
    "information_disclosure": "Information disclosure",
    "denial_of_service": "Denial of service",
    "elevation_of_privilege": "Elevation of privilege",
}

PAD: Final = 16
LABEL_WIDTH: Final = 200
CELL_W: Final = 64
CELL_H: Final = 40
HEADER_H: Final = 40
LEGEND_LINE: Final = 20
FILLS: Final = ("#f1f5f9", "#bfdbfe", "#60a5fa", "#1d4ed8")
TEXT_COLORS: Final = ("#0f172a", "#0f172a", "#0f172a", "#ffffff")


def render_heat_map_svg() -> str:
    ids = sorted(OWASP_LLM)
    counts = heat_map_counts()
    grid_top = PAD + HEADER_H
    grid_left = PAD + LABEL_WIDTH
    legend_top = grid_top + len(STRIDE_CATEGORIES) * CELL_H + 32
    width = grid_left + len(ids) * CELL_W + PAD
    height = legend_top + len(ids) * LEGEND_LINE + 56
    desc = (
        f"Rows are STRIDE categories. Columns are OWASP LLM Top 10 "
        f"{OWASP_LLM_EDITION} entries. Each number is how many suites map to "
        f"that pair."
    )
    out = [
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" '
        f'height="{height}" viewBox="0 0 {width} {height}" role="img" '
        f'aria-labelledby="title desc" font-family="sans-serif">',
        '<title id="title">Threat map: STRIDE by OWASP LLM Top 10</title>',
        f'<desc id="desc">{escape(desc)}</desc>',
        f'<rect width="{width}" height="{height}" fill="#ffffff"/>',
    ]
    for col, owasp_id in enumerate(ids):
        x = grid_left + col * CELL_W + CELL_W // 2
        out.append(
            f'<text x="{x}" y="{grid_top - 12}" font-size="13" '
            f'font-weight="bold" text-anchor="middle" fill="#0f172a">'
            f"{escape(owasp_id)}</text>"
        )
    for row, stride in enumerate(STRIDE_CATEGORIES):
        y = grid_top + row * CELL_H
        out.append(
            f'<text x="{grid_left - 10}" y="{y + CELL_H // 2 + 5}" '
            f'font-size="13" text-anchor="end" fill="#0f172a">'
            f"{escape(STRIDE_LABELS[stride])}</text>"
        )
        for col, owasp_id in enumerate(ids):
            count = counts.get((stride, owasp_id), 0)
            level = min(count, len(FILLS) - 1)
            x = grid_left + col * CELL_W
            out.append(
                f'<rect x="{x}" y="{y}" width="{CELL_W - 2}" '
                f'height="{CELL_H - 2}" fill="{FILLS[level]}" '
                f'data-stride="{stride}" data-owasp="{owasp_id}" '
                f'data-count="{count}"/>'
            )
            if count:
                out.append(
                    f'<text x="{x + (CELL_W - 2) // 2}" '
                    f'y="{y + CELL_H // 2 + 5}" font-size="14" '
                    f'text-anchor="middle" fill="{TEXT_COLORS[level]}">'
                    f"{count}</text>"
                )
    for line, owasp_id in enumerate(ids):
        y = legend_top + line * LEGEND_LINE
        out.append(
            f'<text x="{PAD}" y="{y}" font-size="12" fill="#0f172a">'
            f"{escape(owasp_id)}  {escape(OWASP_LLM[owasp_id])}</text>"
        )
    foot_y = legend_top + len(ids) * LEGEND_LINE + 24
    notes = (
        f"OWASP LLM Top 10 {OWASP_LLM_EDITION}. ATLAS release {ATLAS_RELEASE} "
        f"techniques are listed in threat_map.py and are not drawn here.",
        "A blank cell means no suite maps to that pair, not that the pair is safe.",
    )
    for i, note in enumerate(notes):
        out.append(
            f'<text x="{PAD}" y="{foot_y + i * 16}" font-size="11" '
            f'fill="#334155">{escape(note)}</text>'
        )
    out.append("</svg>")
    return "\n".join(out) + "\n"
