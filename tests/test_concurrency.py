"""Checks that the budget and the proxy hold up when several threads send at once."""

import threading
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from pathlib import Path

import httpx2
from starlette.testclient import TestClient

from redteam_toolkit.limits import BudgetExhaustedError, RequestBudget
from redteam_toolkit.proxy import create_proxy_app
from redteam_toolkit.roe import Limits, RoEGate, load_roe
from tests.roe_samples import VALID, with_window

UPSTREAM = "http://localhost:8000"
QUESTION = {"question": "Who is the support contact?"}


def _nap(_seconds: float) -> None:
    # Why: a real, very short pause inside the lock gives other threads every chance
    # to interfere, without making the test wait for the real request spacing.
    time.sleep(0.001)


def test_the_total_holds_when_many_threads_acquire_at_once() -> None:
    limits = Limits(requests_per_minute=120, total_requests=5, concurrency=1)
    budget = RequestBudget(limits, sleep=_nap)
    outcomes: list[str] = []

    def take() -> None:
        try:
            budget.acquire()
        except BudgetExhaustedError:
            outcomes.append("refused")
        else:
            outcomes.append("ok")

    threads = [threading.Thread(target=take) for _ in range(20)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert outcomes.count("ok") == 5
    assert outcomes.count("refused") == 15
    assert budget.used == 5


def _gate(tmp_path: Path) -> RoEGate:
    now = datetime.now(UTC)
    text = with_window(VALID, now - timedelta(days=1), now + timedelta(days=1))
    path = tmp_path / "roe.toml"
    path.write_text(text)
    return RoEGate(load_roe(path))


def test_the_proxy_never_has_more_requests_in_flight_than_the_file_allows(
    tmp_path: Path,
) -> None:
    lock = threading.Lock()
    state = {"now": 0, "peak": 0}

    def slow(request: httpx2.Request) -> httpx2.Response:
        with lock:
            state["now"] += 1
            state["peak"] = max(state["peak"], state["now"])
        time.sleep(0.03)
        with lock:
            state["now"] -= 1
        return httpx2.Response(200, json={"answer": "ok"})

    limits = Limits(requests_per_minute=120, total_requests=100, concurrency=2)
    app = create_proxy_app(
        _gate(tmp_path),
        target_id="repo1-local",
        suite="prompt_injection",
        upstream_base=UPSTREAM,
        budget=RequestBudget(limits, sleep=_nap),
        client=httpx2.Client(transport=httpx2.MockTransport(slow)),
    )

    def send(_: int) -> int:
        return TestClient(app).post("/query", json=QUESTION).status_code

    with ThreadPoolExecutor(max_workers=8) as pool:
        codes = list(pool.map(send, range(8)))
    assert codes == [200] * 8
    assert state["peak"] <= 2
    assert state["peak"] >= 1
