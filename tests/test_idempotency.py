"""Idempotency-Key claims happen in the database, so two concurrent requests with the
same key start one run and both receive that run's answer. The fake below implements
just enough of db.py to exercise the real idempotent() code without Postgres: its
INSERT never awaits between checking the key and storing the claim, just as a unique
constraint makes the real INSERT atomic."""

import asyncio
import json
from datetime import datetime, timedelta, timezone

import pytest

from fleetwright import api
from fleetwright.actions.core import ActionError, Principal

WHO = Principal(1, "Ada", "operator", token_id=7, token_name="ci")


class FakeIdempotencyDB:
    def __init__(self):
        self.rows = {}
        self.starts = 0

    @staticmethod
    def _can_reclaim(row):
        age = datetime.now(timezone.utc) - row["created"]
        return age > timedelta(days=1) or (row["response"] is None and age > timedelta(minutes=1))

    async def fetchone(self, sql, *args):
        if sql.startswith("INSERT INTO api_idempotency"):
            token_id, key, endpoint, claim = args
            row = self.rows.get((token_id, key))
            if row is not None and not self._can_reclaim(row):
                return None
            self.rows[(token_id, key)] = {"endpoint": endpoint, "claim": claim, "response": None,
                                          "created": datetime.now(timezone.utc)}
            return {"endpoint": endpoint, "claim": claim, "response": None}
        if sql.startswith("SELECT endpoint, response FROM api_idempotency"):
            token_id, key = args
            row = self.rows.get((token_id, key))
            if row is None or self._can_reclaim(row):
                return None
            return {"endpoint": row["endpoint"], "response": row["response"]}
        raise AssertionError(f"unexpected fetchone: {sql}")

    async def execute(self, sql, *args):
        if sql.startswith("UPDATE api_idempotency") and "response = %s" in sql:
            response, token_id, key, claim = args
            row = self.rows.get((token_id, key))
            if row and row["claim"] == claim and row["response"] is None:
                row.update(response=response, claim=None)
                return 1
            return 0
        if sql.startswith("DELETE FROM api_idempotency"):
            token_id, key, claim = args
            row = self.rows.get((token_id, key))
            if row and row["claim"] == claim and row["response"] is None:
                del self.rows[(token_id, key)]
                return 1
            return 0
        raise AssertionError(f"unexpected execute: {sql}")


@pytest.fixture
def fake_db(monkeypatch):
    fake = FakeIdempotencyDB()
    monkeypatch.setattr(api.db, "execute", fake.execute)
    monkeypatch.setattr(api.db, "fetchone", fake.fetchone)
    monkeypatch.setattr(api.db, "J", lambda value: value)
    return fake


def body(response):
    return json.loads(response.body)


def test_without_a_key_every_request_starts(fake_db):
    async def start():
        fake_db.starts += 1
        return {"run_id": fake_db.starts}

    first = asyncio.run(api.idempotent(WHO, None, "POST /runs", start))
    second = asyncio.run(api.idempotent(WHO, "", "POST /runs", start))
    assert [first.status_code, second.status_code] == [201, 201]
    assert [body(first), body(second)] == [{"run_id": 1}, {"run_id": 2}]
    assert fake_db.rows == {}


def test_a_finished_response_is_replayed_and_never_overwritten(fake_db):
    async def start():
        fake_db.starts += 1
        return {"run_id": fake_db.starts}

    first = asyncio.run(api.idempotent(WHO, "same-key", "POST /runs", start))
    second = asyncio.run(api.idempotent(WHO, "same-key", "POST /runs", start))
    assert first.status_code == 201 and second.status_code == 200
    assert body(first) == body(second) == {"run_id": 1}
    assert second.headers["idempotent-replayed"] == "true"
    assert fake_db.starts == 1
    assert fake_db.rows[(WHO.token_id, "same-key")]["response"] == {"run_id": 1}


def test_concurrent_requests_with_one_key_start_only_one_run(fake_db):
    async def start():
        fake_db.starts += 1
        await asyncio.sleep(0.02)      # the other request finds the claim while this one runs
        return {"run_id": 42}

    async def both():
        return await asyncio.gather(
            api.idempotent(WHO, "race-key", "POST /runs", start),
            api.idempotent(WHO, "race-key", "POST /runs", start),
        )

    first, second = asyncio.run(both())
    assert fake_db.starts == 1
    assert [first.status_code, second.status_code] == [201, 200]
    assert body(first) == body(second) == {"run_id": 42}
    assert "idempotent-replayed" not in first.headers
    assert second.headers["idempotent-replayed"] == "true"
    stored = fake_db.rows[(WHO.token_id, "race-key")]
    assert stored["response"] == {"run_id": 42} and stored["claim"] is None


def test_the_same_key_on_a_different_endpoint_conflicts(fake_db):
    async def start():
        fake_db.starts += 1
        return {"run_id": 3}

    asyncio.run(api.idempotent(WHO, "same-key", "POST /runs", start))
    with pytest.raises(ActionError) as e:
        asyncio.run(api.idempotent(WHO, "same-key", "POST /policies/1/run", start))
    assert e.value.status == 409 and e.value.code == "conflict"
    assert fake_db.starts == 1


def test_a_failed_start_releases_the_claim_for_a_waiter(fake_db):
    attempts = 0

    async def start():
        nonlocal attempts
        attempts += 1
        if attempts == 1:
            await asyncio.sleep(0.01)
            raise ActionError("invalid", "No hosts match that target.")
        return {"run_id": 8}

    async def both():
        return await asyncio.gather(
            api.idempotent(WHO, "flaky-key", "POST /runs", start),
            api.idempotent(WHO, "flaky-key", "POST /runs", start),
            return_exceptions=True,
        )

    results = asyncio.run(both())
    assert attempts == 2
    assert sum(isinstance(r, ActionError) for r in results) == 1
    winner = next(r for r in results if isinstance(r, api.JSONResponse))
    assert winner.status_code == 201 and body(winner) == {"run_id": 8}
    assert fake_db.rows[(WHO.token_id, "flaky-key")]["response"] == {"run_id": 8}
