"""Pasted ssh-keyscan keys: parsing, storing them on hosts, and checking them
in the SSH handshake. No Postgres or live SSH server is involved: the action's
db and asyncssh.connect are replaced with small fakes."""

import asyncio
from types import SimpleNamespace

import asyncssh
import pytest

from fleetwright import sshrun, webcommon
from fleetwright.actions import hosts as host_actions
from fleetwright.actions.core import ActionError, Principal
from fleetwright.actions.hosts import parse_known_hosts

WHO = Principal(1, "Ada", "operator")
ED = asyncssh.generate_private_key("ssh-ed25519").export_public_key().decode().strip()
RSA = asyncssh.generate_private_key("ssh-rsa", key_size=2048).export_public_key().decode().strip()


# ─── Parsing ────────────────────────────────────────────────────────────────

def test_pasted_keyscan_output_is_parsed():
    text = f"""# ssh-keyscan web-01,web-02

web-01 {ED}
[web-02]:2222 {RSA}  # a key comment can follow the base64
"""
    entries, errors = parse_known_hosts(text)
    assert errors == []
    assert entries == [("web-01", ED), ("[web-02]:2222", RSA)]


def test_comments_and_blank_lines_alone_are_not_keys():
    assert parse_known_hosts("# nothing\n\n   \n") == ([], [])


@pytest.mark.parametrize("line, hint", [
    ("web-01 ssh-ed25519", "line 2"),
    ("web-01 ssh-dss AAAAB3NzaC1yc2EAAAADAQABAAAB", "line 2"),
    ("web-01 ssh-ed25519 !!!not base64!!!", "line 2"),
    ("web-01 ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQ", "line 2"),   # decodes, but isn't a key
])
def test_malformed_keys_are_reported_with_their_line(line, hint):
    entries, errors = parse_known_hosts(f"web-02 {ED}\n{line}")
    assert entries == [("web-02", ED)]      # one bad line doesn't discard the good ones
    assert len(errors) == 1
    assert hint in errors[0]
    assert "Known host keys" in errors[0]


# ─── Adding and editing hosts ───────────────────────────────────────────────

class FakeHostsDB:
    """Only the queries hosts.add_ssh/edit use."""

    def __init__(self):
        self.inserts, self.updates, self.audits, self.scanned = [], [], [], []
        self._next_id = 1

    async def fetchval(self, sql, *args):
        if sql.startswith("SELECT EXISTS"):
            return True
        if sql.startswith("INSERT INTO hosts"):
            self.inserts.append((sql, args))
            hid, self._next_id = self._next_id, self._next_id + 1
            return hid
        raise AssertionError(f"unexpected fetchval: {sql}")

    async def execute(self, sql, *args):
        self.updates.append((sql, args))
        return 1

    async def audit(self, actor, what):
        self.audits.append((actor, what))


@pytest.fixture
def fake_db(monkeypatch):
    fake = FakeHostsDB()
    monkeypatch.setattr(host_actions.db, "fetchval", fake.fetchval)
    monkeypatch.setattr(host_actions.db, "execute", fake.execute)
    monkeypatch.setattr(host_actions.db, "audit", fake.audit)

    async def queue_scan(ids):
        fake.scanned.append(ids)
        return len(ids)

    monkeypatch.setattr(host_actions.fleet, "queue_scan", queue_scan)
    return fake


def test_add_ssh_stores_the_pasted_keys(fake_db):
    result = asyncio.run(host_actions.add_ssh(
        WHO, [{"name": "web-01", "address": "10.0.0.1", "port": 22}], 7,
        known_hosts=f"web-01 {ED}\nweb-01 {RSA}"))
    assert result["added"] == [1] and fake_db.scanned == [[1]]
    sql, args = fake_db.inserts[0]
    assert "ssh_known_hosts" in sql
    assert args[-1] == [ED, RSA]                 # one per-host known_hosts entry
    assert "ssh_host_key" not in sql             # nothing pinned on first use


def test_add_ssh_matches_keyscan_lines_to_each_host(fake_db):
    asyncio.run(host_actions.add_ssh(
        WHO, [{"name": "web-01", "address": "10.0.0.1", "port": 22},
              {"name": "web-02", "address": "10.0.0.2", "port": 2222}], 7,
        known_hosts=f"web-01 {ED}\n[10.0.0.2]:2222 {RSA}"))
    assert [args[-1] for _, args in fake_db.inserts] == [[ED], [RSA]]


def test_add_ssh_refuses_bad_keys_without_touching_the_database(fake_db):
    with pytest.raises(ActionError) as e:
        asyncio.run(host_actions.add_ssh(
            WHO, [{"name": "web-01", "address": "10.0.0.1", "port": 22}], 7,
            known_hosts=f"web-01 {ED}\nweb-01 ssh-dss AAAAB3NzaC1yc2E"))
    assert e.value.code == "invalid" and "line 2" in e.value.message
    assert fake_db.inserts == [] and fake_db.scanned == []


def test_edit_replaces_and_clears_recorded_keys(fake_db, monkeypatch):
    host = {"id": 1, "name": "web-01", "mode": "ssh", "address": "10.0.0.1", "port": 22,
            "credential_id": 7, "group_id": None, "tags": [], "held": [], "ssh_host_key": "old pinned key",
            "ssh_known_hosts": []}

    async def get(_host_id):
        return dict(host)

    monkeypatch.setattr(host_actions, "_get", get)
    asyncio.run(host_actions.edit(WHO, 1, known_hosts=f"10.0.0.1 {ED}"))
    key_writes = [u for u in fake_db.updates if "ssh_known_hosts" in u[0]]
    sql, args = key_writes[-1]
    assert "ssh_host_key = NULL" in sql and args == ([ED], 1)

    with pytest.raises(ActionError, match="line 1"):
        asyncio.run(host_actions.edit(WHO, 1, known_hosts="10.0.0.1 ssh-ed25519 !!!"))
    asyncio.run(host_actions.edit(WHO, 1, known_hosts=""))
    assert [u for u in fake_db.updates if "ssh_known_hosts" in u[0]][-1][1] == ([], 1)


# ─── The SSH handshake ──────────────────────────────────────────────────────

@pytest.fixture
def connect_spy(monkeypatch):
    """Record asyncssh.connect's kwargs and the DB writes, without a real server."""
    seen = {"writes": []}
    calls = []

    class FakeConn:
        def get_server_host_key(self):
            return SimpleNamespace(export_public_key=lambda: ED.encode())

        def close(self):
            pass

    async def fake_connect(address, **kwargs):
        calls.append((address, kwargs))
        return FakeConn()

    async def no_write(sql, *args):
        seen["writes"].append((sql, args))
        return 1

    monkeypatch.setattr(sshrun.asyncssh, "connect", fake_connect)
    monkeypatch.setattr(sshrun.asyncssh, "import_private_key", lambda _data: object())
    monkeypatch.setattr(sshrun.security, "decrypt", lambda _data: "fake private key")
    monkeypatch.setattr(sshrun.db, "execute", no_write)

    async def cred(_host):
        return {"username": "root", "private_key_enc": "irrelevant to this fake"}

    monkeypatch.setattr(sshrun, "_credential", cred)
    seen["calls"] = calls
    return seen


def host(**changes):
    h = {"id": 9, "address": "10.0.0.1", "port": 22, "credential_id": 7,
         "ssh_host_key": None, "ssh_known_hosts": []}
    h.update(changes)
    return h


def trusted_keys(kwargs):
    return [k.export_public_key().decode().strip() for k in kwargs["known_hosts"][0]]


def test_pasted_keys_are_the_only_keys_accepted_on_connect(connect_spy):
    # A key pinned by an earlier connection must not weaken the pasted set.
    asyncio.run(sshrun.connect(host(ssh_host_key=RSA, ssh_known_hosts=[ED])))
    address, kwargs = connect_spy["calls"][0]
    assert address == "10.0.0.1" and kwargs["port"] == 22
    assert trusted_keys(kwargs) == [ED]
    assert connect_spy["writes"] == []                 # no first-use pinning


def test_without_pasted_keys_a_pinned_key_is_still_used(connect_spy):
    asyncio.run(sshrun.connect(host(ssh_host_key=RSA)))
    assert trusted_keys(connect_spy["calls"][0][1]) == [RSA]
    assert connect_spy["writes"] == []


def test_with_no_keys_at_all_first_contact_is_still_pinned(connect_spy):
    asyncio.run(sshrun.connect(host()))
    assert connect_spy["calls"][0][1]["known_hosts"] is None
    assert "ssh_host_key = %s" in connect_spy["writes"][0][0]
    assert connect_spy["writes"][0][1][0] == ED


def test_a_different_offered_key_is_refused_with_a_useful_message(connect_spy, monkeypatch):
    async def reject(*args, **kwargs):
        raise asyncssh.HostKeyNotVerifiable("offered key is not in the trusted set")

    monkeypatch.setattr(sshrun.asyncssh, "connect", reject)
    with pytest.raises(sshrun.HostKeyMismatch, match="keys recorded for this host"):
        asyncio.run(sshrun.connect(host(ssh_known_hosts=[ED])))


# ─── The UI ─────────────────────────────────────────────────────────────────

def test_add_page_has_a_paste_field():
    html = webcommon.templates.env.get_template("host_new.html").render(
        current_user={"id": 1, "name": "Ada", "email": "ada@example.com", "role": "operator"},
        csrf="token", flashes=[], request=SimpleNamespace(query_params={}),
        form={}, errors=[], keys=[], groups=[])
    assert 'name="known_hosts"' in html
    assert "ssh-keyscan" in html
