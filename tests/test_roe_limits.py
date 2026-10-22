"""The request limit ceilings depend on the kind of authorization.

A self_owned file may only cover local targets, so it may ask for more than a file
backed by a signed document. These are policy ceilings, not measured values.
"""

from pathlib import Path

import pytest

from redteam_toolkit.roe import RoEInvalidError, load_roe
from tests.roe_samples import VALID, change

SIGNED = 'kind = "signed_document"\nsha256 = "' + "a" * 64 + '"'


def _signed(text: str) -> str:
    return change(text, 'kind = "self_owned"', SIGNED)


def _limits(text: str, *, rpm: int, total: int, concurrency: int) -> str:
    text = change(text, "requests_per_minute = 2", f"requests_per_minute = {rpm}")
    text = change(text, "total_requests = 500", f"total_requests = {total}")
    return change(text, "concurrency = 1", f"concurrency = {concurrency}")


def _load(tmp_path: Path, text: str) -> None:
    path = tmp_path / "roe.toml"
    path.write_text(text, encoding="utf-8")
    load_roe(path)


def test_a_self_owned_file_may_use_the_higher_ceilings(tmp_path: Path) -> None:
    _load(tmp_path, _limits(VALID, rpm=60_000, total=100_000, concurrency=50))


def test_a_signed_file_may_use_the_standard_ceilings(tmp_path: Path) -> None:
    _load(tmp_path, _signed(_limits(VALID, rpm=120, total=10_000, concurrency=10)))


@pytest.mark.parametrize(
    ("rpm", "total", "concurrency", "name"),
    [
        (121, 500, 1, "limits.requests_per_minute"),
        (2, 10_001, 1, "limits.total_requests"),
        (2, 500, 11, "limits.concurrency"),
    ],
)
def test_a_signed_file_cannot_use_the_self_owned_ceilings(
    tmp_path: Path, rpm: int, total: int, concurrency: int, name: str
) -> None:
    text = _signed(_limits(VALID, rpm=rpm, total=total, concurrency=concurrency))
    with pytest.raises(RoEInvalidError, match=name):
        _load(tmp_path, text)


@pytest.mark.parametrize(
    ("rpm", "total", "concurrency"),
    [(60_001, 500, 1), (2, 100_001, 1), (2, 500, 51)],
)
def test_nothing_may_pass_the_self_owned_ceilings(
    tmp_path: Path, rpm: int, total: int, concurrency: int
) -> None:
    with pytest.raises(RoEInvalidError, match="limits"):
        _load(tmp_path, _limits(VALID, rpm=rpm, total=total, concurrency=concurrency))
