"""The probe image builder. It ships no attack text, and neither do these tests.

The two injection strings are the ones already defined in test_stub_target.py.
"""

import io
from collections.abc import Callable

import pytest
from fastapi import FastAPI
from PIL import Image
from starlette.testclient import TestClient

from redteam_toolkit.image_probe import MAX_TEXT_CHARS, render_probe_image
from redteam_toolkit.stub_target import (
    EXTRACTED_TEXT_KEY,
    extract_text,
    hardened_app,
    weak_app,
)
from tests.test_stub_target import PLAIN_INJECTION, SPACED_INJECTION

LONG = "word " * 300


def _image(data: bytes) -> Image.Image:
    return Image.open(io.BytesIO(data))


def test_the_result_is_a_png_of_a_sensible_size() -> None:
    with _image(render_probe_image(PLAIN_INJECTION)) as image:
        assert image.format == "PNG"
        assert image.size[0] == 620
        assert 40 <= image.size[1] <= 200


def test_the_text_is_drawn_so_the_image_is_not_blank() -> None:
    with _image(render_probe_image(PLAIN_INJECTION)) as image:
        darkest = min(image.convert("L").tobytes())
    assert darkest < 128


def test_a_longer_text_makes_a_taller_image() -> None:
    with _image(render_probe_image(PLAIN_INJECTION)) as short:
        short_height = short.size[1]
    with _image(render_probe_image(LONG[:1500])) as long:
        assert long.size[1] > short_height


def test_the_text_goes_into_the_metadata_only_when_a_key_is_given() -> None:
    with _image(render_probe_image(PLAIN_INJECTION, metadata_key="note")) as image:
        image.load()
        assert image.info["note"] == PLAIN_INJECTION
    with _image(render_probe_image(PLAIN_INJECTION)) as image:
        image.load()
        assert "note" not in image.info


@pytest.mark.parametrize("text", ["", "   ", "\n"])
def test_empty_text_is_refused(text: str) -> None:
    with pytest.raises(ValueError, match="empty"):
        render_probe_image(text)


def test_text_over_the_limit_is_refused() -> None:
    with pytest.raises(ValueError, match="over 2000"):
        render_probe_image("a" * (MAX_TEXT_CHARS + 1))


@pytest.mark.parametrize("key", ["", "1abc", "a" * 80, "bad/key"])
def test_a_bad_metadata_key_is_refused(key: str) -> None:
    with pytest.raises(ValueError, match="PNG text keyword"):
        render_probe_image(PLAIN_INJECTION, metadata_key=key)


def test_non_latin_text_survives_in_the_metadata() -> None:
    text = "বাংলা " + PLAIN_INJECTION
    with _image(render_probe_image(text, metadata_key="note")) as image:
        image.load()
        assert image.info["note"] == text


def test_the_stub_stand_in_reads_the_text_back() -> None:
    data = render_probe_image(SPACED_INJECTION, metadata_key=EXTRACTED_TEXT_KEY)
    assert extract_text(data) == SPACED_INJECTION


def _post(factory: Callable[[], FastAPI], data: bytes) -> int:
    client = TestClient(factory(), base_url="http://localhost:8000")
    response = client.post(
        "/ingest/image", files={"file": ("probe.png", data, "image/png")}
    )
    status: int = response.status_code
    return status


def test_the_weak_stub_accepts_and_the_hardened_stub_blocks_a_built_probe() -> None:
    data = render_probe_image(PLAIN_INJECTION, metadata_key=EXTRACTED_TEXT_KEY)
    assert _post(weak_app, data) == 201
    assert _post(hardened_app, data) == 400


def test_a_built_probe_without_the_metadata_has_nothing_for_the_stand_in() -> None:
    assert _post(weak_app, render_probe_image(PLAIN_INJECTION)) == 422
