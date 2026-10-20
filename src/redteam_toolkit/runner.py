"""Sends one gated HTTP request to a target and records what came back.

Every call goes through RoEGate.permit first. permit raises RoEViolationError
and this module sends nothing if the request is not authorized. There is no
path in this module that reaches the network without going through permit.

This module does no scoring and ships no attack content of its own. It is
plumbing: given a URL and a JSON body, send it, catch the connection failure
modes, and return what happened. The caller decides what to send and what
the result means.
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Any

import httpx2

from redteam_toolkit.limits import RequestBudget
from redteam_toolkit.roe import RoEGate

DEFAULT_TIMEOUT_SECONDS = 10.0


@dataclass(frozen=True, slots=True)
class ProbeResult:
    """What happened when one request was sent. No judgement is made here."""

    target_id: str
    suite: str
    url: str
    status_code: int | None
    body: str
    elapsed_seconds: float
    error: str | None

    @property
    def ok(self) -> bool:
        return self.error is None and self.status_code is not None


def send_probe(
    gate: RoEGate,
    *,
    target_id: str,
    suite: str,
    url: str,
    json_body: dict[str, Any],
    client: httpx2.Client | None = None,
    timeout: float = DEFAULT_TIMEOUT_SECONDS,
    budget: RequestBudget | None = None,
) -> ProbeResult:
    """Check the gate, then send one POST request. Never raises on a network error.

    Raises RoEViolationError if the gate refuses. That is a programming error in
    the caller, not a result to record, so it is not caught here. With a budget,
    this also waits for the next free slot, and raises BudgetExhaustedError (a
    RoEViolationError) once the file's total_requests is used up. The budget is
    only charged after the gate allows the request, so a refusal costs nothing.
    """
    gate.permit(target_id=target_id, suite=suite, url=url)
    if budget is not None:
        budget.acquire()
    owns_client = client is None
    http_client = client or httpx2.Client(
        timeout=timeout, follow_redirects=False, trust_env=False
    )
    started = time.monotonic()
    try:
        response = http_client.post(url, json=json_body)
    except httpx2.HTTPError as exc:
        return ProbeResult(
            target_id=target_id,
            suite=suite,
            url=url,
            status_code=None,
            body="",
            elapsed_seconds=time.monotonic() - started,
            error=f"{type(exc).__name__}: {exc}",
        )
    finally:
        if owns_client:
            http_client.close()
    return ProbeResult(
        target_id=target_id,
        suite=suite,
        url=url,
        status_code=response.status_code,
        body=response.text,
        elapsed_seconds=time.monotonic() - started,
        error=None,
    )
