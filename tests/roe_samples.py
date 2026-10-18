"""Sample Rules of Engagement text shared by the tests."""

import json
from datetime import datetime

TARGET_BODY = """\
id = "repo1-local"
base_url = "http://localhost:8000"
allowed_paths = ["/query", "/query/stream"]
environment = "local"
real_personal_data = false
"""

VALID = (
    """\
schema_version = 1
engagement_id = "repo1-local-selftest"
credentials_env_var = "TARGET_TOKEN_LOCAL"
allowed_suites = ["prompt_injection", "pii_leakage"]

[client]
name = "Fazle Rabbi (self test)"

[authorized_by]
name = "Fazle Rabbi"
role = "System owner"
email = "mfrabbi.ai@gmail.com"

[operator]
name = "Fazle Rabbi"
role = "Operator"
email = "mfrabbi.ai@gmail.com"

[window]
start = 2026-10-18T00:00:00+06:00
end = 2026-10-25T00:00:00+06:00

[limits]
requests_per_minute = 2
total_requests = 500
concurrency = 1

[authorization]
kind = "self_owned"
reference = "Own system, local machine only"

[stop_contact]
name = "Fazle Rabbi"
role = "Operator"
email = "mfrabbi.ai@gmail.com"

[[targets]]
"""
    + TARGET_BODY
)

PRODUCTION_APPROVAL = """
[targets.production_approval]
name = "Pat Example"
role = "CTO"
email = "cto@example.com"
"""


def change(text: str, old: str, new: str) -> str:
    """Replace the first ``old`` with ``new``. Fail loudly if ``old`` is missing."""
    if old not in text:
        raise AssertionError(f"sample does not contain {old!r}")
    return text.replace(old, new, 1)


def with_window(text: str, start: datetime, end: datetime) -> str:
    text = change(
        text, "start = 2026-10-18T00:00:00+06:00", f"start = {start.isoformat()}"
    )
    return change(text, "end = 2026-10-25T00:00:00+06:00", f"end = {end.isoformat()}")


def with_start(raw: str) -> str:
    """VALID with the window start replaced by ``raw`` (TOML text, not a datetime)."""
    return change(VALID, "start = 2026-10-18T00:00:00+06:00", f"start = {raw}")


def with_end(raw: str) -> str:
    return change(VALID, "end = 2026-10-25T00:00:00+06:00", f"end = {raw}")


def with_url(url: str) -> str:
    return change(VALID, 'base_url = "http://localhost:8000"', f'base_url = "{url}"')


def with_environment(name: str) -> str:
    return change(VALID, 'environment = "local"', f'environment = "{name}"')


def with_suites(raw: str) -> str:
    """VALID with the suite list replaced by ``raw`` (TOML text)."""
    return change(VALID, '["prompt_injection", "pii_leakage"]', raw)


def with_paths(text: str, paths: list[str]) -> str:
    return change(
        text,
        'allowed_paths = ["/query", "/query/stream"]',
        f"allowed_paths = {json.dumps(paths)}",
    )


def production(*, approval: bool = True) -> str:
    """A valid production engagement: https target, signed document, second approver."""
    text = change(
        VALID,
        'base_url = "http://localhost:8000"',
        'base_url = "https://app.example.com"',
    )
    text = change(text, 'environment = "local"', 'environment = "production"')
    text = change(
        text,
        'kind = "self_owned"',
        'kind = "signed_document"\nsha256 = "' + "a" * 64 + '"',
    )
    return text + PRODUCTION_APPROVAL if approval else text
