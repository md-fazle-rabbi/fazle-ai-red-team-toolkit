import pytest

from redteam_toolkit.target_client import (
    MAX_TIMEOUT_SECONDS,
    TargetClientError,
    build_client,
    parse_header_spec,
    resolve_headers,
)

FAKE_VALUE = "fake-test-value-1234"


def test_parse_header_spec_splits_name_and_variable() -> None:
    assert parse_header_spec("X-Tenant-ID=REPO1_TEST_TENANT") == (
        "X-Tenant-ID",
        "REPO1_TEST_TENANT",
    )


@pytest.mark.parametrize(
    "spec",
    [
        "",
        "X-Tenant-ID",
        "=REPO1_TEST_TENANT",
        "X-Tenant-ID=",
        "X-Tenant-ID=lowercase",
        "X Tenant=REPO1_TEST_TENANT",
        "X-Tenant-ID=REPO1 TEST",
        "Authorization=Bearer abc",
    ],
)
def test_parse_header_spec_rejects_bad_shapes(spec: str) -> None:
    with pytest.raises(TargetClientError, match="must look like"):
        parse_header_spec(spec)


@pytest.mark.parametrize("name", ["Host", "content-length", "Content-Type"])
def test_parse_header_spec_rejects_headers_the_client_owns(name: str) -> None:
    with pytest.raises(TargetClientError, match="set by the client"):
        parse_header_spec(f"{name}=SOME_VAR")


def test_error_never_echoes_the_spec() -> None:
    with pytest.raises(TargetClientError) as excinfo:
        parse_header_spec(f"Authorization=Bearer {FAKE_VALUE}")
    assert FAKE_VALUE not in str(excinfo.value)


def test_resolve_headers_reads_values_and_strips_whitespace() -> None:
    environ = {"REPO1_TEST_TENANT": f"  {FAKE_VALUE}\n"}
    assert resolve_headers(["X-Tenant-ID=REPO1_TEST_TENANT"], environ) == {
        "X-Tenant-ID": FAKE_VALUE
    }


def test_resolve_headers_rejects_missing_and_empty_variables() -> None:
    with pytest.raises(TargetClientError, match="REPO1_TEST_TENANT is not set"):
        resolve_headers(["X-Tenant-ID=REPO1_TEST_TENANT"], {})
    with pytest.raises(TargetClientError, match="REPO1_TEST_TENANT is not set"):
        resolve_headers(["X-Tenant-ID=REPO1_TEST_TENANT"], {"REPO1_TEST_TENANT": " "})


def test_resolve_headers_rejects_control_characters_without_the_value() -> None:
    environ = {"REPO1_TEST_TENANT": f"{FAKE_VALUE}\r\nX-Evil: 1"}
    with pytest.raises(TargetClientError, match="control character") as excinfo:
        resolve_headers(["X-Tenant-ID=REPO1_TEST_TENANT"], environ)
    assert FAKE_VALUE not in str(excinfo.value)


def test_resolve_headers_rejects_a_repeated_header_name() -> None:
    environ = {"VAR_ONE": "a", "VAR_TWO": "b"}
    with pytest.raises(TargetClientError, match="same header name"):
        resolve_headers(["X-Tenant-ID=VAR_ONE", "x-tenant-id=VAR_TWO"], environ)


def test_resolve_headers_with_no_specs_is_empty() -> None:
    assert resolve_headers([], {}) == {}


def test_build_client_sets_headers_timeout_and_safe_defaults() -> None:
    environ = {"REPO1_TEST_TENANT": FAKE_VALUE}
    client = build_client(
        header_specs=["X-Tenant-ID=REPO1_TEST_TENANT"],
        timeout=30.0,
        environ=environ,
    )
    try:
        assert client.headers["X-Tenant-ID"] == FAKE_VALUE
        assert client.timeout.read == 30.0
        assert client.follow_redirects is False
        assert client.trust_env is False
    finally:
        client.close()


@pytest.mark.parametrize("timeout", [0.0, -1.0, MAX_TIMEOUT_SECONDS + 1, float("nan")])
def test_build_client_rejects_a_bad_timeout(timeout: float) -> None:
    with pytest.raises(TargetClientError, match="timeout must be"):
        build_client(timeout=timeout, environ={})
