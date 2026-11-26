"""Retrying a run starts a fresh run with the original settings, not a copy of its state."""

import asyncio
from datetime import datetime, timezone

from fleetwright.actions import runs
from fleetwright.actions.core import Principal

WHO = Principal(7, "Rae", "operator")


def _run(**overrides) -> dict:
    """A runs row as the action reads it."""
    row = {"id": 12, "kind": "apply", "title": "Security updates", "created_by": "Rae",
           "policy_id": 3, "booking_id": 9, "selection": {"mode": "kinds", "kinds": ["security"]},
           "batch_size": 0, "canary": False, "max_failures": 2, "reboot": "if_needed",
           "window_end": None, "on_window_close": "finish_started", "status": "done",
           "current_batch": 1, "note": None,
           "created_at": datetime(2026, 11, 26, 8, tzinfo=timezone.utc),
           "finished_at": datetime(2026, 11, 26, 9, tzinfo=timezone.utc)}
    row.update(overrides)
    return row


def _retry(monkeypatch, run: dict, failed_hosts: list[int]) -> tuple[dict, dict]:
    """Run the action against a stubbed database and capture create_run's settings."""
    created = []

    async def fetchone(sql, *args):
        assert args == (run["id"],)
        return dict(run)

    async def fetch(sql, *args):
        assert args == (run["id"],)
        return [{"host_id": host_id} for host_id in failed_hosts]

    async def create_run(**kwargs):
        created.append(kwargs)
        return 99

    monkeypatch.setattr(runs.db, "fetchone", fetchone)
    monkeypatch.setattr(runs.db, "fetch", fetch)
    monkeypatch.setattr(runs.fleet, "create_run", create_run)
    result = asyncio.run(runs.retry(WHO, run["id"]))
    assert len(created) == 1
    return result, created[0]


def _expected(run: dict, hosts: list[int]) -> dict:
    return {"kind": run["kind"],
            "title": run["title"].removesuffix(" (retry)") + " (retry)",
            "actor": WHO.actor, "host_ids": hosts, "selection": run["selection"],
            "batch_size": run["batch_size"], "canary": run["canary"],
            "max_failures": run["max_failures"], "reboot": run["reboot"],
            "window_end": run["window_end"], "on_window_close": run["on_window_close"]}


def test_retry_keeps_canary_and_maintenance_window(monkeypatch):
    window_end = datetime(2026, 11, 26, 10, 30, tzinfo=timezone.utc)
    run = _run(title="Security updates (retry)", batch_size=0, canary=True,
               window_end=window_end, on_window_close="stop")
    result, kwargs = _retry(monkeypatch, run, [12, 3])

    assert result == {"run_id": 99}
    assert kwargs == _expected(run, [12, 3])
    assert kwargs["canary"] is True and kwargs["batch_size"] == 0
    assert kwargs["window_end"] == window_end and kwargs["on_window_close"] == "stop"


def test_retry_without_canary_or_window_still_works(monkeypatch):
    run = _run()
    result, kwargs = _retry(monkeypatch, run, [5])

    assert result == {"run_id": 99}
    assert kwargs == _expected(run, [5])
    assert kwargs["canary"] is False and kwargs["window_end"] is None
    assert kwargs["on_window_close"] == "finish_started"
