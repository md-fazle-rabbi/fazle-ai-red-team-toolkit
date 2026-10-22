"""Tests for the Rules of Engagement schema and gate.

Most of these try to break the gate on purpose: bad input, scope tricks and
look-alike URLs. Each one must be refused.
"""

import hashlib
from datetime import UTC, datetime, timedelta, timezone
from pathlib import Path

import pytest

from redteam_toolkit.roe import (
    MAX_FILE_BYTES,
    LoadedRoE,
    RoEGate,
    RoEInvalidError,
    RoEMissingError,
    RoEViolationError,
    load_roe,
)
from tests.roe_samples import (
    PRODUCTION_APPROVAL,
    TARGET_BODY,
    VALID,
    change,
    production,
    with_end,
    with_environment,
    with_paths,
    with_start,
    with_suites,
    with_url,
    with_window,
)

EXAMPLE = Path(__file__).resolve().parent.parent / "examples" / "roe.repo1-local.toml"
INSIDE = datetime(2026, 10, 20, 12, 0, tzinfo=UTC)
DHAKA = timezone(timedelta(hours=6))


def _write(tmp_path: Path, text: str) -> Path:
    path = tmp_path / "roe.toml"
    path.write_text(text, encoding="utf-8")
    return path


def _load(tmp_path: Path, text: str) -> LoadedRoE:
    return load_roe(_write(tmp_path, text))


def _gate(tmp_path: Path, text: str = VALID) -> RoEGate:
    return RoEGate(_load(tmp_path, text))


# --- loading ---------------------------------------------------------------------


def test_valid_file_loads_and_records_its_hash(tmp_path: Path) -> None:
    loaded = _load(tmp_path, VALID)
    assert loaded.roe.engagement_id == "repo1-local-selftest"
    assert loaded.roe.targets[0].id == "repo1-local"
    assert loaded.sha256 == hashlib.sha256(VALID.encode("utf-8")).hexdigest()


def test_quoted_iso_window_is_accepted(tmp_path: Path) -> None:
    text = with_start('"2026-10-18T00:00:00+06:00"')
    assert _load(tmp_path, text).roe.window.start.utcoffset() == timedelta(hours=6)


def test_valid_production_engagement_loads(tmp_path: Path) -> None:
    assert _load(tmp_path, production()).roe.targets[0].environment == "production"


def test_shipped_example_is_valid() -> None:
    assert load_roe(EXAMPLE).roe.targets[0].id == "repo1-local"


def test_no_path_is_refused() -> None:
    with pytest.raises(RoEMissingError, match="No file, no run"):
        load_roe(None)


def test_missing_file_is_refused(tmp_path: Path) -> None:
    with pytest.raises(RoEMissingError, match="Cannot read"):
        load_roe(tmp_path / "nope.toml")


def test_directory_is_refused(tmp_path: Path) -> None:
    with pytest.raises(RoEMissingError, match="Cannot read"):
        load_roe(tmp_path)


def test_oversized_file_is_refused(tmp_path: Path) -> None:
    with pytest.raises(RoEInvalidError, match="larger than"):
        _load(tmp_path, "#" * (MAX_FILE_BYTES + 1))


def test_file_that_is_not_utf8_is_refused(tmp_path: Path) -> None:
    path = tmp_path / "roe.toml"
    path.write_bytes(b"\xff\xfe\x00")
    with pytest.raises(RoEInvalidError, match="TOML"):
        load_roe(path)


def test_broken_toml_is_refused(tmp_path: Path) -> None:
    with pytest.raises(RoEInvalidError, match="TOML"):
        _load(tmp_path, "schema_version = \n")


def test_duplicate_keys_are_refused(tmp_path: Path) -> None:
    twice = "schema_version = 1\nschema_version = 1\n"
    text = change(VALID, "schema_version = 1\n", twice)
    with pytest.raises(RoEInvalidError, match="TOML"):
        _load(tmp_path, text)


# --- schema ----------------------------------------------------------------------

INVALID = [
    pytest.param(
        change(VALID, "[limits]\n", '[limits]\npassword = "hunter2"\n'),
        "limits.password",
        id="unknown key",
    ),
    pytest.param(
        change(VALID, "schema_version = 1", "schema_version = 2"),
        "schema_version",
        id="unknown schema version",
    ),
    pytest.param(
        with_start("2026-10-18T00:00:00"),
        "window.start",
        id="window without UTC offset",
    ),
    pytest.param(
        with_start("2026-10-18"),
        "window.start",
        id="window with a date only",
    ),
    pytest.param(
        with_start('"tomorrow"'),
        "window.start",
        id="window with a word",
    ),
    pytest.param(
        with_end("2026-10-17T00:00:00+06:00"),
        "must be after",
        id="window ends before it starts",
    ),
    pytest.param(
        with_end("2026-12-25T00:00:00+06:00"),
        "longer than",
        id="window too long",
    ),
    pytest.param(
        change(VALID, "requests_per_minute = 2", "requests_per_minute = 70000"),
        "limits.requests_per_minute",
        id="rate above the ceiling",
    ),
    pytest.param(
        change(VALID, "requests_per_minute = 2", "requests_per_minute = 0"),
        "limits.requests_per_minute",
        id="rate of zero",
    ),
    pytest.param(
        change(VALID, "total_requests = 500", "total_requests = 200000"),
        "limits.total_requests",
        id="total above the ceiling",
    ),
    pytest.param(
        change(VALID, "concurrency = 1", "concurrency = 51"),
        "limits.concurrency",
        id="concurrency above the ceiling",
    ),
    pytest.param(
        change(VALID, "concurrency = 1", "concurrency = 1.5"),
        "limits.concurrency",
        id="concurrency as a fraction",
    ),
    pytest.param(
        change(VALID, "real_personal_data = false", "real_personal_data = true"),
        "real_personal_data",
        id="real personal data in scope",
    ),
    pytest.param(
        change(VALID, "real_personal_data = false", 'real_personal_data = "no"'),
        "real_personal_data",
        id="real personal data as a string",
    ),
    pytest.param(
        change(VALID, "real_personal_data = false\n", ""),
        "real_personal_data",
        id="real personal data missing",
    ),
    pytest.param(
        with_url("ftp://localhost"),
        "targets.0.base_url",
        id="wrong scheme",
    ),
    pytest.param(
        with_url("http://:8000"),
        "targets.0.base_url",
        id="no host",
    ),
    pytest.param(
        with_url("http://a@localhost"),
        "targets.0.base_url",
        id="credentials in the URL",
    ),
    pytest.param(
        with_url("http://localhost:99999"),
        "targets.0.base_url",
        id="port out of range",
    ),
    pytest.param(
        with_url("http://local host"),
        "targets.0.base_url",
        id="space in the URL",
    ),
    pytest.param(
        with_url(""),
        "targets.0.base_url",
        id="empty URL",
    ),
    pytest.param(
        with_url("http://localhost:8000/api"),
        "targets.0.base_url",
        id="path in the base URL",
    ),
    pytest.param(
        with_url("http://localhost:8000#x"),
        "targets.0.base_url",
        id="fragment in the base URL",
    ),
    pytest.param(
        with_url("http://example.com"),
        "must use localhost",
        id="local target on a remote host",
    ),
    pytest.param(
        with_environment("staging"),
        "must use https",
        id="staging over http",
    ),
    pytest.param(
        production(approval=False),
        "production_approval",
        id="production without a second approver",
    ),
    pytest.param(
        change(
            production(),
            'email = "cto@example.com"',
            'email = "MFRabbi.ai@gmail.com"',
        ),
        "different person",
        id="production approved by the same person",
    ),
    pytest.param(
        change(
            with_url("https://staging.example.com"),
            'environment = "local"',
            'environment = "staging"',
        ),
        "self_owned",
        id="self owned authorization on a remote target",
    ),
    pytest.param(
        VALID + "\n[[targets]]\n" + TARGET_BODY,
        "duplicate target id",
        id="duplicate target ids",
    ),
    pytest.param(
        with_suites('["pii_leakage", "pii_leakage"]'),
        "duplicate suite",
        id="duplicate suites",
    ),
    pytest.param(
        with_suites('["nuke"]'),
        "allowed_suites.0",
        id="unknown suite",
    ),
    pytest.param(
        with_suites("[]"),
        "allowed_suites",
        id="no suites",
    ),
    pytest.param(
        change(VALID, 'kind = "self_owned"', 'kind = "signed_document"'),
        "sha256 is required",
        id="signed document without a hash",
    ),
    pytest.param(
        change(
            VALID,
            'kind = "self_owned"',
            'kind = "signed_document"\nsha256 = "abc"',
        ),
        "authorization.sha256",
        id="signed document with a bad hash",
    ),
    pytest.param(
        change(
            VALID,
            'credentials_env_var = "TARGET_TOKEN_LOCAL"',
            'credentials_env_var = "token"',
        ),
        "credentials_env_var",
        id="environment variable name in lower case",
    ),
    pytest.param(
        change(VALID, 'email = "mfrabbi.ai@gmail.com"', 'email = "not-an-email"'),
        "authorized_by.email",
        id="bad email",
    ),
]


@pytest.mark.parametrize(("text", "expected"), INVALID)
def test_invalid_files_are_refused(tmp_path: Path, text: str, expected: str) -> None:
    with pytest.raises(RoEInvalidError) as excinfo:
        _load(tmp_path, text)
    message = str(excinfo.value)
    assert expected in message
    # Why: the message shows where a problem is, never the value that caused it.
    assert "hunter2" not in message


@pytest.mark.parametrize(
    "path",
    ["query", "/", "/a/../b", "/q?x=1", "/q#x", "/q%2e", "//q", "/a b"],
)
def test_unsafe_allowed_paths_are_refused(tmp_path: Path, path: str) -> None:
    with pytest.raises(RoEInvalidError, match="allowed_paths"):
        _load(tmp_path, with_paths(VALID, [path]))


def test_production_approval_block_is_part_of_the_sample() -> None:
    # Why: guards the sample itself. If the approval block ever stopped matching, the
    # "without a second approver" case above would pass for the wrong reason.
    assert PRODUCTION_APPROVAL in production()
    assert PRODUCTION_APPROVAL not in production(approval=False)


# --- the gate: who, what, when ---------------------------------------------------


def test_gate_exposes_engagement_and_hash(tmp_path: Path) -> None:
    gate = _gate(tmp_path)
    assert gate.engagement_id == "repo1-local-selftest"
    assert gate.sha256 == hashlib.sha256(VALID.encode("utf-8")).hexdigest()


def test_permit_returns_the_target(tmp_path: Path) -> None:
    target = _gate(tmp_path).permit(
        target_id="repo1-local", suite="prompt_injection", now=INSIDE
    )
    assert target.id == "repo1-local"


def test_permit_uses_the_clock_by_default(tmp_path: Path) -> None:
    now = datetime.now(UTC)
    text = with_window(VALID, now - timedelta(days=1), now + timedelta(days=1))
    target = _gate(tmp_path, text).permit(target_id="repo1-local", suite="pii_leakage")
    assert target.id == "repo1-local"


def test_window_start_is_inclusive(tmp_path: Path) -> None:
    start = datetime(2026, 10, 18, 0, 0, tzinfo=DHAKA)
    _gate(tmp_path).permit(target_id="repo1-local", suite="pii_leakage", now=start)


def test_before_the_window_is_refused(tmp_path: Path) -> None:
    early = datetime(2026, 10, 10, tzinfo=UTC)
    with pytest.raises(RoEViolationError, match="not opened"):
        _gate(tmp_path).permit(target_id="repo1-local", suite="pii_leakage", now=early)


def test_window_end_is_exclusive(tmp_path: Path) -> None:
    end = datetime(2026, 10, 25, 0, 0, tzinfo=DHAKA)
    with pytest.raises(RoEViolationError, match="closed"):
        _gate(tmp_path).permit(target_id="repo1-local", suite="pii_leakage", now=end)


def test_naive_clock_value_is_a_programming_error(tmp_path: Path) -> None:
    naive = datetime(2026, 10, 20, 12, 0)
    with pytest.raises(ValueError, match="timezone-aware"):
        _gate(tmp_path).permit(target_id="repo1-local", suite="pii_leakage", now=naive)


def test_unknown_target_is_refused(tmp_path: Path) -> None:
    with pytest.raises(RoEViolationError, match="not listed"):
        _gate(tmp_path).permit(target_id="other", suite="pii_leakage", now=INSIDE)


def test_suite_outside_the_list_is_refused(tmp_path: Path) -> None:
    with pytest.raises(RoEViolationError, match="not authorized"):
        _gate(tmp_path).permit(target_id="repo1-local", suite="jailbreak", now=INSIDE)


# --- the gate: URLs --------------------------------------------------------------


@pytest.mark.parametrize(
    "url",
    [
        "http://localhost:8000/query",
        "http://localhost:8000/query/",
        "http://localhost:8000/query/stream",
        "http://localhost:8000/query/stream?x=1",
        "HTTP://LOCALHOST:8000/query",
    ],
)
def test_authorized_urls_are_permitted(tmp_path: Path, url: str) -> None:
    target = _gate(tmp_path).permit(
        target_id="repo1-local", suite="pii_leakage", url=url, now=INSIDE
    )
    assert target.id == "repo1-local"


@pytest.mark.parametrize(
    "url",
    [
        "",
        "http://localhost:8000",
        "http://localhost:8000/admin",
        "http://localhost:8000/query-evil",
        "http://localhost:8001/query",
        "https://localhost:8000/query",
        "http://example.com:8000/query",
        "http://localhost.example.com:8000/query",
        "http://localhost:8000@evil.example/query",
        "http://evil.example@localhost:8000/query",
        "http://localhost:8000/query/../admin",
        "http://localhost:8000/query/%2e%2e/admin",
        "http://localhost:8000/query/%252e%252e/admin",
        "http://localhost:8000/query/a%20b",
        "http://localhost:8000/query/a\\b",
        "http://localhost:8000/query//x",
        "http://local host:8000/query",
        "ftp://localhost:8000/query",
    ],
)
def test_urls_outside_the_target_are_refused(tmp_path: Path, url: str) -> None:
    with pytest.raises(RoEViolationError):
        _gate(tmp_path).permit(
            target_id="repo1-local", suite="pii_leakage", url=url, now=INSIDE
        )


def test_default_port_matches_an_explicit_default_port(tmp_path: Path) -> None:
    gate = _gate(tmp_path, production())
    gate.permit(
        target_id="repo1-local",
        suite="pii_leakage",
        url="https://app.example.com:443/query",
        now=INSIDE,
    )
    with pytest.raises(RoEViolationError):
        gate.permit(
            target_id="repo1-local",
            suite="pii_leakage",
            url="https://app.example.com:8443/query",
            now=INSIDE,
        )
