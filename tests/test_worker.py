"""Housekeeping is woken by finished tasks, with the 5 s tick as a safety net."""

import asyncio
import time
from types import SimpleNamespace

import pytest

from fleetwright import worker


class _Result:
    async def fetchone(self):
        return {"ok": True}


class _Conn:
    """Just enough of a pooled connection for the scheduler's advisory lock."""

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return False

    async def execute(self, sql, args=None):
        return _Result()


class _Pool:
    def connection(self):
        return _Conn()


@pytest.fixture
def ticks(monkeypatch):
    """Housekeeping against a fake DB and notifier, recording scheduler passes."""
    seen = []

    async def record(*args):
        seen.append(time.monotonic())

    async def noop(*args):
        pass

    monkeypatch.setattr(worker.db, "pool", lambda: _Pool())
    monkeypatch.setattr(worker.fleet, "schedule_tick", noop)
    monkeypatch.setattr(worker.fleet, "advance_runs", record)   # once per pass
    monkeypatch.setattr(worker.Worker, "due_scans", noop)
    monkeypatch.setattr(worker.Worker, "sweep", noop)
    monkeypatch.setattr(worker.notify, "check_unreachable", noop)
    monkeypatch.setattr(worker.notify, "check_backup", noop)
    return seen


async def until(predicate, timeout=1.0):
    deadline = time.monotonic() + timeout
    while not predicate():
        if time.monotonic() >= deadline:
            raise AssertionError("condition was not met in time")
        await asyncio.sleep(0.005)


async def stop(task):
    task.cancel()
    await asyncio.gather(task, return_exceptions=True)


def test_a_completed_task_wakes_housekeeping_before_the_tick(ticks, monkeypatch):
    monkeypatch.setattr(worker, "HOUSEKEEPING_DEBOUNCE", 0.02)

    async def scenario():
        w = worker.Worker()
        task = asyncio.create_task(w.housekeeping())
        try:
            await until(lambda: len(ticks) >= 1)
            first = ticks[-1]
            w.on_notification("done")          # what finish_task NOTIFYs
            await until(lambda: len(ticks) >= 2)
            assert 0 < ticks[-1] - first < 1.0  # well before the 5 s tick
        finally:
            await stop(task)

    asyncio.run(scenario())


def test_a_burst_of_completions_is_one_housekeeping_pass(ticks, monkeypatch):
    monkeypatch.setattr(worker, "HOUSEKEEPING_DEBOUNCE", 0.3)

    async def scenario():
        w = worker.Worker()
        task = asyncio.create_task(w.housekeeping())

        async def burst():            # spread over time, all inside one debounce window
            for _ in range(10):
                w.on_notification("done")
                await asyncio.sleep(0.01)

        try:
            await until(lambda: len(ticks) >= 1)
            asyncio.create_task(burst())
            await asyncio.sleep(0.8)
            assert len(ticks) == 2
            assert not w.housekeeping_wake.is_set()
        finally:
            await stop(task)

    asyncio.run(scenario())


def test_only_task_completions_are_relevant():
    w = worker.Worker()
    for payload in ("123", "scan", ""):
        w.on_notification(payload)
        assert not w.housekeeping_wake.is_set()
    assert w.wake.is_set()                      # claiming still wakes on every change
    w.on_notification("done")
    assert w.housekeeping_wake.is_set()


def test_periodic_tick_still_works_without_notifications(ticks, monkeypatch):
    monkeypatch.setattr(worker, "HOUSEKEEPING_INTERVAL", 0.05)

    async def scenario():
        w = worker.Worker()
        task = asyncio.create_task(w.housekeeping())
        try:
            await until(lambda: len(ticks) >= 3)
            assert not w.housekeeping_wake.is_set()
        finally:
            await stop(task)

    asyncio.run(scenario())


def test_listener_passes_notify_payloads_to_the_wake_handler(monkeypatch):
    class _ListenConn:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *exc):
            return False

        async def execute(self, sql):
            return None

        async def notifies(self):
            yield SimpleNamespace(payload="done")
            await asyncio.Event().wait()

    async def connect(*args, **kwargs):
        return _ListenConn()

    monkeypatch.setattr(worker.psycopg.AsyncConnection, "connect", connect)

    async def scenario():
        w = worker.Worker()
        task = asyncio.create_task(w.listen())
        try:
            await until(lambda: w.housekeeping_wake.is_set())
            assert w.wake.is_set()
        finally:
            await stop(task)

    asyncio.run(scenario())
