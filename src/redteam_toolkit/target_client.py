"""Builds the HTTP client for a run against a real target.

A run against a real target has to send a credential, such as a tenant header or a
bearer token. This module reads each header value from an environment variable at
run time. The command line only ever carries the NAMES (header name and variable
name), so a secret never lands in shell history, a summary or an error message.

The client it builds is handed to send_probe, so the Rules of Engagement gate and the
request budget still apply to every request. This module sends nothing itself.
"""

from __future__ import annotations

import argparse
import os
import re
from collections.abc import Mapping, Sequence
from typing import Final

import httpx2

from redteam_toolkit.runner import DEFAULT_TIMEOUT_SECONDS

# Why: Repo 1's stage deadlines in query.py add up to 105 seconds in the worst case. A
# longer wait than this is a hung run, not a slow target. This is a policy value I
# chose, not a measured one.
MAX_TIMEOUT_SECONDS: Final = 120.0

_HEADER_NAME: Final = re.compile(r"[A-Za-z][A-Za-z0-9-]{0,63}")
# Why: the same shape as the environment variable names the Rules of Engagement file
# accepts, so one rule covers both.
_ENV_NAME: Final = re.compile(r"[A-Z][A-Z0-9_]{1,63}")
_CONTROL_CHARS: Final = re.compile(r"[\x00-\x1f\x7f]")
# Why: the HTTP client sets these itself. Overriding them could break a multipart
# upload or change how the request is framed.
_FORBIDDEN_HEADERS: Final = frozenset(
    {"host", "content-length", "content-type", "transfer-encoding", "connection"}
)


class TargetClientError(ValueError):
    """The header or timeout settings cannot be used. Nothing was sent."""


def parse_header_spec(spec: str) -> tuple[str, str]:
    """Split NAME=ENV_VAR into (header name, variable name).

    Errors never quote the spec. A person who pastes a secret here by mistake must
    not see it echoed back or written to a log.
    """
    name, separator, env_name = spec.partition("=")
    if (
        not separator
        or not _HEADER_NAME.fullmatch(name)
        or not _ENV_NAME.fullmatch(env_name)
    ):
        raise TargetClientError(
            "a header spec must look like HEADER-NAME=ENV_VAR_NAME, "
            "where the variable holds the value"
        )
    if name.lower() in _FORBIDDEN_HEADERS:
        raise TargetClientError("that header is set by the client and cannot be given")
    return name, env_name


def resolve_headers(
    specs: Sequence[str], environ: Mapping[str, str] | None = None
) -> dict[str, str]:
    """Read every header value from the environment. Raises TargetClientError.

    The value is the whole header value, so an Authorization variable holds
    "Bearer ..." in full. Only the variable NAME ever appears in an error.
    """
    source = os.environ if environ is None else environ
    headers: dict[str, str] = {}
    seen: set[str] = set()
    for spec in specs:
        name, env_name = parse_header_spec(spec)
        if name.lower() in seen:
            raise TargetClientError("two header specs use the same header name")
        seen.add(name.lower())
        value = source.get(env_name, "").strip()
        if not value:
            raise TargetClientError(
                f"environment variable {env_name} is not set or is empty"
            )
        # Why: a newline in a header value is how a second header gets smuggled in.
        if _CONTROL_CHARS.search(value):
            raise TargetClientError(
                f"environment variable {env_name} holds a control character"
            )
        headers[name] = value
    return headers


def build_client(
    *,
    header_specs: Sequence[str] = (),
    timeout: float = DEFAULT_TIMEOUT_SECONDS,
    environ: Mapping[str, str] | None = None,
) -> httpx2.Client:
    """Build a client with the given headers and timeout. The caller closes it.

    Redirects are off and the proxy environment is ignored, like send_probe's own
    client, so a credential cannot follow a redirect to another host.
    """
    if not 0 < timeout <= MAX_TIMEOUT_SECONDS:
        raise TargetClientError(
            f"timeout must be above 0 and at most {MAX_TIMEOUT_SECONDS:g} seconds"
        )
    return httpx2.Client(
        headers=resolve_headers(header_specs, environ),
        timeout=timeout,
        follow_redirects=False,
        trust_env=False,
    )


def add_client_arguments(parser: argparse.ArgumentParser) -> None:
    """Add --header-env and --timeout to a command that sends requests."""
    parser.add_argument(
        "--header-env",
        action="append",
        default=[],
        metavar="HEADER=ENV_VAR",
        help=(
            "send HEADER with the value held in environment variable ENV_VAR "
            "(repeat for more). Give the names only, never the value"
        ),
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=DEFAULT_TIMEOUT_SECONDS,
        metavar="SECONDS",
        help=(
            "seconds to wait for each response "
            f"(default: {DEFAULT_TIMEOUT_SECONDS:g}, at most {MAX_TIMEOUT_SECONDS:g})"
        ),
    )


def client_from_args(args: argparse.Namespace) -> httpx2.Client | None:
    """Build the client the options ask for, or None when they ask for nothing.

    None means send_probe builds its own client for each request, exactly as it did
    before these options existed. The caller closes a client that is returned.
    """
    header_specs: list[str] = args.header_env
    timeout: float = args.timeout
    if not header_specs and timeout == DEFAULT_TIMEOUT_SECONDS:
        return None
    return build_client(header_specs=header_specs, timeout=timeout)
