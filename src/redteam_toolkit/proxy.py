"""A local proxy that puts the Rules of Engagement gate in front of other tools.

Tools such as garak send their own HTTP requests and never call send_probe. Point
such a tool at this proxy instead of the target. Every request is then checked by
the gate and counted by the budget before it is forwarded, and every outcome goes
to an audit record. That includes a POST whose body is not a JSON object, which is
rejected before anything is sent. Only POST requests are audited, because nothing
else is ever forwarded.

One proxy serves one target and one suite, fixed when it is created. The tool
cannot choose a different suite or a different host by changing its request.
With a budget, at most the file's concurrency requests are in flight at once.
Request and response bodies are never written to the audit record, because they
can hold personal data or secrets.
"""

from __future__ import annotations

import json
import threading
from collections.abc import Callable
from contextlib import AbstractContextManager, nullcontext
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Annotated, Any

import httpx2
from fastapi import Body, FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse, Response

from redteam_toolkit.limits import RequestBudget
from redteam_toolkit.roe import RoEGate, RoEViolationError
from redteam_toolkit.runner import send_probe


@dataclass(frozen=True, slots=True)
class AuditEntry:
    time: str
    target_id: str
    suite: str
    path: str
    outcome: str  # "forwarded", "refused", "rejected" or "upstream_error"
    status_code: int | None
    detail: str


AuditSink = Callable[[AuditEntry], None]


class JsonlAudit:
    """Appends one JSON object per line. Holds no bodies, only the outcome."""

    def __init__(self, path: Path) -> None:
        self._path = path

    def __call__(self, entry: AuditEntry) -> None:
        with self._path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(asdict(entry), sort_keys=True) + "\n")


def create_proxy_app(
    gate: RoEGate,
    *,
    target_id: str,
    suite: str,
    upstream_base: str,
    budget: RequestBudget | None = None,
    client: httpx2.Client | None = None,
    audit: AuditSink | None = None,
) -> FastAPI:
    app = FastAPI(title="redteam-toolkit gated proxy")
    base = upstream_base.rstrip("/")
    slots = (
        threading.BoundedSemaphore(budget.concurrency) if budget is not None else None
    )

    def record(path: str, outcome: str, status: int | None, detail: str) -> None:
        if audit is not None:
            audit(
                AuditEntry(
                    time=datetime.now(UTC).isoformat(),
                    target_id=target_id,
                    suite=suite,
                    path=path,
                    outcome=outcome,
                    status_code=status,
                    detail=detail,
                )
            )

    @app.exception_handler(RequestValidationError)
    def reject_malformed(request: Request, exc: Exception) -> JSONResponse:
        # Why: FastAPI refuses a body that is not a JSON object before forward() runs,
        # so without this the request would leave no audit record. The reply carries
        # no part of the body, and neither does the audit entry.
        del exc
        message = "the request body is not a JSON object"
        record(request.url.path.lstrip("/"), "rejected", 422, message)
        return JSONResponse(status_code=422, content={"rejected": message})

    @app.post("/{path:path}")
    def forward(path: str, body: Annotated[dict[str, Any], Body()]) -> Response:
        guard: AbstractContextManager[object] = (
            slots if slots is not None else nullcontext()
        )
        try:
            with guard:
                result = send_probe(
                    gate,
                    target_id=target_id,
                    suite=suite,
                    url=f"{base}/{path}",
                    json_body=body,
                    client=client,
                    budget=budget,
                )
        except RoEViolationError as exc:
            record(path, "refused", 403, str(exc))
            return JSONResponse(status_code=403, content={"refused": str(exc)})
        if not result.ok:
            record(path, "upstream_error", None, str(result.error))
            return JSONResponse(status_code=502, content={"error": result.error})
        record(path, "forwarded", result.status_code, "")
        return Response(
            content=result.body,
            status_code=result.status_code or 502,
            media_type="application/json",
        )

    return app
