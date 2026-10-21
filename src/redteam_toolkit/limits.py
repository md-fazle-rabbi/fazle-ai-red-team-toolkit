"""Enforces the request limits from the Rules of Engagement file.

RoEGate.permit says whether one request is in scope. It says nothing about how fast
or how many requests are sent. RequestBudget does that part: it counts requests
against total_requests and spaces them out to stay under requests_per_minute.

Everything here lives in memory, and the count starts at zero in every new process.
acquire is safe to call from several threads: a lock makes each caller take its turn,
so the count and the spacing stay right. The file's concurrency limit is exposed as a
property. This class does not enforce it, because it never sees a request finish. A
caller that sends from several threads has to hold that many slots itself, as the
gated proxy does.
"""

import threading
import time
from collections.abc import Callable

from redteam_toolkit.roe import Limits, RoEViolationError

SECONDS_PER_MINUTE = 60.0


class BudgetExhaustedError(RoEViolationError):
    """The file's total_requests is used up. Nothing more may be sent."""


class RequestBudget:
    """Counts requests and spaces them evenly. Raises when the total is used up."""

    def __init__(
        self,
        limits: Limits,
        *,
        clock: Callable[[], float] = time.monotonic,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        self._limits = limits
        self._clock = clock
        self._sleep = sleep
        self._used = 0
        self._last: float | None = None
        self._lock = threading.Lock()

    @property
    def used(self) -> int:
        return self._used

    @property
    def concurrency(self) -> int:
        """The limit from the file. A concurrent runner has to enforce it itself."""
        return self._limits.concurrency

    def acquire(self) -> None:
        """Take one request from the budget, waiting if the last one was too recent.

        Even spacing, not bursts: a target with a free tier limit sees the rate the
        file asked for, with no spike at the start of each minute.
        """
        with self._lock:
            if self._used >= self._limits.total_requests:
                raise BudgetExhaustedError(
                    f"The file authorizes {self._limits.total_requests} requests "
                    "and all of them are used"
                )
            if self._last is not None:
                interval = SECONDS_PER_MINUTE / self._limits.requests_per_minute
                wait = self._last + interval - self._clock()
                if wait > 0:
                    self._sleep(wait)
            self._last = self._clock()
            self._used += 1
