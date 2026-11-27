"""Enrolment end to end: an agent's own instance id decides which host it is,
even when several containers report the same machine id, hostname and boot id.
An agent that doesn't send one still uses the old machine/hostname/boot checks."""

import asyncio
from types import SimpleNamespace

import pytest

from fleetwright import fleet, gateway, security

TOKEN = "an-enrolment-token-for-these-tests"   # only its hash is ever kept
ID_A = "11111111-1111-4111-8111-111111111111"
ID_B = "22222222-2222-4222-8222-222222222222"
SHARED = {"hostname": "web", "machine_id": "machine-a", "boot_id": "kernel-boot",
          "address": "10.9.0.1", "os_id": "ubuntu", "os_version": "24.04", "family": "apt"}


class FakeDB:
    """Just the queries enroll() and record_facts() make, against in-memory hosts."""

    def __init__(self):
        self.hosts = []
        self.audit_log = []
        self.next_id = 1

    async def fetchone(self, sql, *args):
        if "UPDATE enroll_tokens" in sql:
            return {"id": 7, "group_id": None, "tags": [], "label": "test token"} \
                if args[0] == security.token_hash(TOKEN) else None
        if "WHERE name = %s" in sql:
            return next((h for h in self.hosts if h["name"] == args[0]), None)
        raise AssertionError(f"unexpected fetchone: {sql}")

    async def fetch(self, sql, *args):
        assert "SELECT id, name, hostname" in sql
        machine, _, instance, _ = args
        return [dict(h) for h in sorted(self.hosts, key=lambda h: h["id"])
                if h["mode"] == "agent"
                and ((machine and h["machine_id"] == machine)
                     or (instance and h["instance_id"] == instance))]

    async def fetchval(self, sql, *args):
        assert "INSERT INTO hosts" in sql
        name, address, group, tags, token_hash, _pin, instance = args
        host = {"id": self.next_id, "name": name, "address": address, "mode": "agent",
                "group_id": group, "tags": tags, "agent_token_hash": token_hash,
                "instance_id": instance, "machine_id": None, "hostname": None,
                "boot_id": None, "agent_connected": False}
        self.next_id += 1
        self.hosts.append(host)
        return host["id"]

    async def execute(self, sql, *args):
        if "UPDATE enroll_tokens" in sql:
            return 1
        if "UPDATE hosts SET agent_token_hash" in sql:
            token_hash, _pin, instance, host_id = args
            h = self._host(host_id)
            h["agent_token_hash"] = token_hash
            h["instance_id"] = instance or h["instance_id"]
            return 1
        if "UPDATE hosts SET os_id" in sql:
            h = self._host(args[-1])
            keys = ("os_id", "os_version", "os_pretty", "family", "kernel", "boot_id",
                    "booted_at", "machine_id", "instance_id", "hostname")
            for key, value in zip(keys, args):
                if value is not None:
                    h[key] = value
            return 1
        raise AssertionError(f"unexpected execute: {sql}")

    async def audit(self, actor, what):
        self.audit_log.append((actor, what))

    def _host(self, host_id):
        return next(h for h in self.hosts if h["id"] == host_id)


@pytest.fixture
def db(monkeypatch):
    fake = FakeDB()
    monkeypatch.setattr(gateway, "db", fake)
    monkeypatch.setattr(fleet, "db", fake)
    return fake


def enroll(facts):
    class Request:
        client = SimpleNamespace(host="192.0.2.10")

        async def json(self):
            return {"token": TOKEN, "facts": facts}

    return asyncio.run(gateway.enroll(Request()))


def facts(instance=None, **changes):
    return dict(SHARED, instance_id=instance, **changes)


def test_two_containers_with_identical_legacy_facts_get_two_hosts(db):
    # Same image: same machine id, hostname and kernel boot id. Only the agents'
    # own instance ids differ, and neither enrolment may take over the other host.
    a = enroll(facts(ID_A))
    token_a = db.hosts[0]["agent_token_hash"]
    b = enroll(facts(ID_B))
    assert b["host_id"] != a["host_id"]
    assert b["name"] != a["name"]
    assert [h["instance_id"] for h in db.hosts] == [ID_A, ID_B]
    assert db.hosts[0]["agent_token_hash"] == token_a
    assert db.hosts[0]["agent_token_hash"] != db.hosts[1]["agent_token_hash"]
    assert "same /etc/machine-id" in db.audit_log[-1][1]


def test_a_reinstall_with_the_same_instance_id_keeps_its_host(db):
    first = enroll(facts(ID_A))
    again = enroll(facts(ID_A, machine_id="machine-b", boot_id="boot-b"))
    assert again["host_id"] == first["host_id"]
    assert again["name"] == first["name"]
    assert "Re-enrolled" in db.audit_log[-1][1]


def test_an_agent_without_an_instance_id_uses_the_old_checks(db):
    first = enroll(facts())
    db.hosts[0]["agent_connected"] = True   # install.sh enrols before restarting the old agent
    again = enroll(facts())
    assert again["host_id"] == first["host_id"]
    assert db.audit_log[-1][1].startswith("Re-enrolled")

    # A clone with a different boot id while the original is connected still gets
    # a host of its own: the legacy fallback hasn't gone away.
    clone = enroll(facts(boot_id="boot-b"))
    assert clone["host_id"] != first["host_id"]


def test_an_upgraded_legacy_host_records_its_instance_id(db):
    first = enroll(facts())
    asyncio.run(fleet.record_facts(first["host_id"], facts(ID_A)))
    assert db.hosts[0]["instance_id"] == ID_A
    assert enroll(facts(ID_A))["host_id"] == first["host_id"]
    assert enroll(facts(ID_B))["host_id"] != first["host_id"]
