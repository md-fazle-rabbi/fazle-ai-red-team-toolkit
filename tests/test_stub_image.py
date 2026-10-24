"""The stub's POST /ingest/image: Repo 1's checks, and a stand-in for text extraction.

The stand-in reads a text entry the test puts in the PNG. These tests do not read
pixels and do not test a vision model. The two injection strings are the ones already
defined in test_stub_target.py. This module adds no new attack content.
"""

import io
import json
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest
from fastapi import FastAPI
from PIL import Image
from PIL.PngImagePlugin import PngInfo
from starlette.testclient import TestClient

from redteam_toolkit.stub_target import (
    ALLOWED_IMAGE_FORMATS,
    EXTRACTED_TEXT_KEY,
    MAX_IMAGE_PIXELS,
    ImageIngestResponse,
    hardened_app,
    weak_app,
)
from tests.test_stub_contract import _fields
from tests.test_stub_target import PLAIN_INJECTION, SPACED_INJECTION

CONTRACT = (
    Path(__file__).parent.parent / "contracts" / "repo1-ingest-image-contract.json"
)
BENIGN = "Opening hours are nine to five on weekdays."


def _png(text: str | None, size: tuple[int, int] = (64, 32)) -> bytes:
    info = PngInfo()
    if text is not None:
        info.add_text(EXTRACTED_TEXT_KEY, text)
    out = io.BytesIO()
    Image.new("RGB", size, "white").save(out, "PNG", pnginfo=info)
    return out.getvalue()


def _post(factory: Callable[[], FastAPI], data: bytes) -> Any:
    client = TestClient(factory(), base_url="http://localhost:8000")
    return client.post(
        "/ingest/image", files={"file": ("probe.png", data, "image/png")}
    )


def test_the_weak_stub_accepts_an_image_with_an_injection() -> None:
    response = _post(weak_app, _png(PLAIN_INJECTION))
    assert response.status_code == 201
    body = response.json()
    assert body["modality"] == "image"
    assert body["deduplicated"] is False


def test_the_hardened_stub_blocks_the_plain_injection() -> None:
    response = _post(hardened_app, _png(PLAIN_INJECTION))
    assert response.status_code == 400
    assert "possible prompt injection" in response.json()["detail"]


def test_the_hardened_stub_misses_the_spaced_variant() -> None:
    # Why: this is the same gap the text firewall has, and the reason the suite exists.
    assert _post(hardened_app, _png(SPACED_INJECTION)).status_code == 201


def test_the_hardened_stub_accepts_a_harmless_image() -> None:
    assert _post(hardened_app, _png(BENIGN)).status_code == 201


def test_the_same_image_twice_is_deduplicated() -> None:
    client = TestClient(weak_app(), base_url="http://localhost:8000")
    data = _png(BENIGN)
    files = {"file": ("probe.png", data, "image/png")}
    first = client.post("/ingest/image", files=files)
    second = client.post("/ingest/image", files=files)
    assert second.status_code == 201
    assert second.json()["deduplicated"] is True
    assert second.json()["document_id"] == first.json()["document_id"]


def test_an_empty_file_is_refused() -> None:
    response = _post(weak_app, b"")
    assert response.status_code == 400
    assert response.json()["detail"] == "Empty file"


@pytest.mark.parametrize("fmt", ["GIF", "BMP"])
def test_a_format_repo1_does_not_accept_is_refused(fmt: str) -> None:
    out = io.BytesIO()
    Image.new("RGB", (8, 8), "white").save(out, fmt)
    response = _post(weak_app, out.getvalue())
    assert response.status_code == 415


def test_a_file_that_is_not_an_image_is_refused() -> None:
    assert _post(weak_app, b"not an image").status_code == 415


def test_an_image_with_too_many_pixels_is_refused() -> None:
    size = (8000, 7000)
    assert size[0] * size[1] > MAX_IMAGE_PIXELS
    out = io.BytesIO()
    Image.new("1", size).save(out, "PNG")
    response = _post(weak_app, out.getvalue())
    assert response.status_code == 422
    assert "50,000,000 pixels" in response.json()["detail"]


def test_an_image_past_pillows_own_warning_is_refused() -> None:
    out = io.BytesIO()
    Image.new("1", (10000, 10000)).save(out, "PNG")
    response = _post(weak_app, out.getvalue())
    assert response.status_code == 422
    assert "too many pixels" in response.json()["detail"]


@pytest.mark.parametrize("data", [_png(None), _png("   ")])
def test_a_png_with_no_extracted_text_is_refused(data: bytes) -> None:
    response = _post(weak_app, data)
    assert response.status_code == 422
    assert "No text could be extracted" in response.json()["detail"]


def test_a_jpeg_has_no_extracted_text_in_the_stand_in() -> None:
    out = io.BytesIO()
    Image.new("RGB", (16, 16), "white").save(out, "JPEG")
    assert _post(weak_app, out.getvalue()).status_code == 422


def _contract() -> dict[str, Any]:
    loaded: dict[str, Any] = json.loads(CONTRACT.read_text(encoding="utf-8"))
    return loaded


def test_the_response_fields_match_the_contract() -> None:
    assert _fields(ImageIngestResponse) == _contract()["response"]["fields"]


def test_the_limits_match_the_contract() -> None:
    limits = _contract()["limits"]
    assert limits["max_image_pixels"] == MAX_IMAGE_PIXELS
    assert sorted(ALLOWED_IMAGE_FORMATS) == limits["allowed_formats"]


def test_the_stub_error_messages_are_in_the_contract() -> None:
    errors = _contract()["errors"]
    stub_only = _contract()["stub_only_errors"]
    assert "Empty file" in errors["400"]
    assert "Unsupported image. Upload a PNG, JPEG or WEBP file." in errors["415"]
    assert "The image has too many pixels." in errors["422"]
    assert "No text could be extracted from the image." in stub_only["422"]
