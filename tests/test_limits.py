"""Tests for the request budget. A fake clock makes them instant and exact."""

import pytest

from redteam_toolkit.limits import BudgetExhaustedError, RequestBudget
from redteam_toolkit.roe import Limits, RoEViolationError


class FakeTime:
    """A clock that only moves when a test moves it or the budget sleeps."""

    def __init__(self) -> None:
        self.now = 1000.0
        self.sleeps: list[float] = []

    def clock(self) -> float:
        return self.now

    def sleep(self, seconds: float) -> None:
        self.sleeps.append(seconds)
        self.now += seconds


def _budget(
    fake: FakeTime, *, rpm: int = 60, total: int = 100, concurrency: int = 1
) -> RequestBudget:
    limits = Limits(
        requests_per_minute=rpm, total_requests=total, concurrency=concurrency
    )
    return RequestBudget(limits, clock=fake.clock, sleep=fake.sleep)


def test_the_first_request_does_not_wait() -> None:
    fake = FakeTime()
    budget = _budget(fake)
    budget.acquire()
    assert fake.sleeps == []
    assert budget.used == 1


def test_a_second_request_waits_for_the_full_interval() -> None:
    fake = FakeTime()
    budget = _budget(fake, rpm=30)
    budget.acquire()
    budget.acquire()
    assert fake.sleeps == [2.0]


def test_a_request_after_a_pause_waits_only_for_the_rest() -> None:
    fake = FakeTime()
    budget = _budget(fake, rpm=30)
    budget.acquire()
    fake.now += 0.5
    budget.acquire()
    assert fake.sleeps == [1.5]


def test_no_wait_when_enough_time_has_passed() -> None:
    fake = FakeTime()
    budget = _budget(fake, rpm=30)
    budget.acquire()
    fake.now += 2.0
    budget.acquire()
    assert fake.sleeps == []
    assert budget.used == 2


def test_requests_stay_evenly_spaced_over_many_calls() -> None:
    fake = FakeTime()
    budget = _budget(fake, rpm=20)
    start = fake.now
    for _ in range(5):
        budget.acquire()
    assert fake.now - start == pytest.approx(4 * 3.0)


def test_the_total_is_enforced_and_nothing_is_counted_after_it() -> None:
    fake = FakeTime()
    budget = _budget(fake, total=2)
    budget.acquire()
    budget.acquire()
    with pytest.raises(BudgetExhaustedError):
        budget.acquire()
    assert budget.used == 2


def test_an_exhausted_budget_does_not_sleep() -> None:
    fake = FakeTime()
    budget = _budget(fake, total=1)
    budget.acquire()
    with pytest.raises(BudgetExhaustedError):
        budget.acquire()
    assert fake.sleeps == []


def test_exhaustion_is_a_gate_style_refusal() -> None:
    fake = FakeTime()
    budget = _budget(fake, total=1)
    budget.acquire()
    with pytest.raises(RoEViolationError):
        budget.acquire()


def test_concurrency_is_exposed_from_the_file() -> None:
    assert _budget(FakeTime(), concurrency=4).concurrency == 4


def test_defaults_use_the_real_clock_and_sleep() -> None:
    limits = Limits(requests_per_minute=120, total_requests=2, concurrency=1)
    budget = RequestBudget(limits)
    budget.acquire()
    assert budget.used == 1
