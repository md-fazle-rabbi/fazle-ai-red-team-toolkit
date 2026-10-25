"""Builds a probe image from a line of text the caller supplies.

This module ships no attack text. It is plumbing: given a string, it draws the string
on a white canvas so a vision model has pixels to read, and it can also store the same
string in a PNG text entry. The local stub has no vision model and reads that entry
instead. A real target ignores the entry and reads the pixels, so both are written.

The caller decides what text to send and what the result means.
"""

from __future__ import annotations

import io
import re
import textwrap
from typing import Final

from PIL import Image, ImageDraw, ImageFont
from PIL.PngImagePlugin import PngInfo

MAX_TEXT_CHARS: Final = 2000
_WRAP_CHARS: Final = 60
_FONT_SIZE: Final = 16
_LINE_HEIGHT: Final = 22
_MARGIN: Final = 10
_WIDTH: Final = 2 * _MARGIN + 600
# Why: PNG text keywords are 1 to 79 characters. This keeps them plain.
_KEY: Final = re.compile(r"[A-Za-z][A-Za-z0-9_ .-]{0,78}")


def render_probe_image(text: str, *, metadata_key: str | None = None) -> bytes:
    """Return PNG bytes with `text` drawn in black on white.

    With metadata_key, the same text is also stored in a PNG text entry under that key.
    Raises ValueError for empty text, text over MAX_TEXT_CHARS, or a bad key.
    """
    if not text.strip():
        raise ValueError("the probe text is empty")
    if len(text) > MAX_TEXT_CHARS:
        raise ValueError(f"the probe text is over {MAX_TEXT_CHARS} characters")
    if metadata_key is not None and not _KEY.fullmatch(metadata_key):
        raise ValueError("the metadata key is not a valid PNG text keyword")
    lines = textwrap.wrap(text, width=_WRAP_CHARS) or [text.strip()]
    height = 2 * _MARGIN + _LINE_HEIGHT * len(lines)
    image = Image.new("RGB", (_WIDTH, height), "white")
    draw = ImageDraw.Draw(image)
    font = ImageFont.load_default(size=_FONT_SIZE)
    for index, line in enumerate(lines):
        draw.text(
            (_MARGIN, _MARGIN + index * _LINE_HEIGHT), line, fill="black", font=font
        )
    info = PngInfo()
    if metadata_key is not None:
        info.add_text(metadata_key, text.strip())
    out = io.BytesIO()
    image.save(out, "PNG", pnginfo=info)
    return out.getvalue()
