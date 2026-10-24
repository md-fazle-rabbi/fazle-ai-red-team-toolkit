"""The image ingest snapshot must stay consistent with itself and the query snapshot.

contracts/repo1-ingest-image-contract.json is copied by hand from Repo 1. These tests
catch a bad edit to it. They do not catch Repo 1 changing after the snapshot was taken.
"""

import json
from pathlib import Path
from typing import Any

CONTRACTS = Path(__file__).parent.parent / "contracts"


def _load(name: str) -> dict[str, Any]:
    loaded: dict[str, Any] = json.loads((CONTRACTS / name).read_text(encoding="utf-8"))
    return loaded


def test_both_snapshots_come_from_the_same_repo_commit() -> None:
    image = _load("repo1-ingest-image-contract.json")
    query = _load("repo1-query-contract.json")
    assert image["source"]["repo"] == query["source"]["repo"]
    assert image["source"]["commit"] == query["source"]["commit"]


def test_the_body_limit_is_the_image_limit_plus_the_multipart_overhead() -> None:
    limits = _load("repo1-ingest-image-contract.json")["limits"]
    assert limits["max_body_bytes"] == (
        limits["max_image_bytes"] + limits["multipart_overhead_bytes"]
    )


def test_the_endpoint_is_a_multipart_upload_of_one_file_field() -> None:
    endpoint = _load("repo1-ingest-image-contract.json")["endpoint"]
    assert endpoint == {
        "method": "POST",
        "path": "/ingest/image",
        "content_type": "multipart/form-data",
        "file_field": "file",
    }


def test_the_allowed_formats_and_error_statuses_are_listed() -> None:
    contract = _load("repo1-ingest-image-contract.json")
    assert contract["limits"]["allowed_formats"] == ["JPEG", "PNG", "WEBP"]
    assert set(contract["errors"]) == {"400", "415", "422"}
    assert contract["response"]["status_code"] == 201
