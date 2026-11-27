"""Enrolment validates the request before spending a token: a malformed facts payload
must not use up a single-use token and lock the real agent out."""

import asyncio
from types import SimpleNamespace

import pytest
from fastapi import HTTPException

from fleetwright import db, gateway

VALID_FACTS = {"hostname": "web-01", "machine_id": "machine-1", "boot_id": "boot-1",
               "address": "10.0.0.1", "os_id": "ubuntu", "booted_at": 1760000000}
TOKEN = "an-enrolment-token"


class FakeRequest:
    def __init__(self, body):
        self.body = body
        self.client = SimpleNamespace(host="127.0.0.1")

    async def json(self):
        return self.body


@pytest.fixture
def token_db(monkeypatch):
    """One single-use token, and just enough of the database for an enrolment."""
    state = {"uses_left": 1}
    calls = []

    async def fetchone(sql, *args):
        calls.append(sql)
        if "UPDATE enroll_tokens" not in sql:
            return None
        if state["uses_left"] <= 0:
            return None
        state["uses_left"] -= 1
        return {"id": 11, "group_id": 1, "tags": None, "label": "test token"}

    async def fetch(sql, *args):
        return []

    async def fetchval(sql, *args):
        assert sql.lstrip().startswith("INSERT INTO hosts")
        return 42

    async def execute(sql, *args):
        return 1

    async def audit(actor, what):
        calls.append(what)

    monkeypatch.setattr(db, "fetchone", fetchone)
    monkeypatch.setattr(db, "fetch", fetch)
    monkeypatch.setattr(db, "fetchval", fetchval)
    monkeypatch.setattr(db, "execute", execute)
    monkeypatch.setattr(db, "audit", audit)
    return state, calls


def post(body):
    return asyncio.run(gateway.enroll(FakeRequest(body)))


BAD_BODIES = [
    {"token": TOKEN, "facts": "oops"},                       # the reported case
    {"token": TOKEN, "facts": ["web-01"]},
    {"token": TOKEN, "facts": 7},
    {"token": TOKEN},                                        # facts missing
    {"token": TOKEN, "facts": {"hostname": ["web-01"]}},     # right shape, wrong field type
    "oops",                                                  # not an object at all
]


@pytest.mark.parametrize("body", BAD_BODIES)
def test_a_bad_request_is_400_and_leaves_the_token_alone(token_db, body):
    state, calls = token_db
    with pytest.raises(HTTPException) as e:
        post(body)
    assert e.value.status_code == 400
    assert state["uses_left"] == 1
    assert not any("UPDATE enroll_tokens" in sql for sql in calls)


def test_a_valid_enrolment_still_spends_one_use(token_db):
    state, calls = token_db
    result = post({"token": TOKEN, "facts": VALID_FACTS})
    assert state["uses_left"] == 0
    assert sum("UPDATE enroll_tokens" in sql for sql in calls) == 1
    assert result["host_id"] == 42 and result["name"] == "web-01" and result["agent_token"]


def test_a_used_up_token_is_still_refused(token_db):
    state, _ = token_db
    state["uses_left"] = 0
    with pytest.raises(HTTPException) as e:
        post({"token": TOKEN, "facts": VALID_FACTS})
    assert e.value.status_code == 403
    assert state["uses_left"] == 0
