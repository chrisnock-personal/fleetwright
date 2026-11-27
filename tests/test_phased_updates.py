"""Ubuntu phased updates: a second apt simulation says what phasing withholds.
Those packages stay out of the pending counts and policies, but reach the host
row and the host page with an explanation of why they aren't installed yet."""

import asyncio
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from pathlib import Path

from starlette.requests import Request

from fleetwright import fleet, pkgops
from fleetwright.webcommon import templates

ROOT = Path(__file__).resolve().parent.parent
OPTION = "APT::Get::Always-Include-Phased-Updates=true"

APT_SIM = """\
NOTE: This is only a simulation!
Inst liblzma5 [5.6.1] (5.6.2 Ubuntu:24.04/noble-updates, Ubuntu:24.04/noble-security [amd64])
Inst apt [2.8.3] (2.8.4 Ubuntu:24.04/noble-updates [amd64])
Conf liblzma5 (5.6.2 Ubuntu:24.04/noble-updates, Ubuntu:24.04/noble-security [amd64])
The following packages have been kept back:
  libnss3
0 upgraded, 0 newly installed, 0 to remove and 1 not upgraded.
"""

PHASED_SIM = """\
NOTE: This is only a simulation!
Inst liblzma5 [5.6.1] (5.6.2 Ubuntu:24.04/noble-updates, Ubuntu:24.04/noble-security [amd64])
Inst apt [2.8.3] (2.8.4 Ubuntu:24.04/noble-updates [amd64])
Inst libnss3 [3.98] (3.99 Ubuntu:24.04/noble-updates [amd64])
Inst curl [8.0] (8.1 Ubuntu:24.04/noble-updates [amd64])
Inst libnewdep (1.0 Ubuntu:24.04/noble-updates [amd64])
0 upgraded, 0 newly installed, 0 to remove and 0 not upgraded.
"""


def test_phased_updates_from_simulations():
    # libnewdep is a dependency of a phased upgrade, not itself phased.
    assert pkgops.phased_updates_from_simulations(APT_SIM, PHASED_SIM) == ["curl", "libnss3"]


def test_phased_updates_from_matching_simulations():
    assert pkgops.phased_updates_from_simulations(APT_SIM, APT_SIM) == []


def _run(monkeypatch, phased_output=PHASED_SIM):
    commands = []

    def fake_run(cmd, log=None, **kwargs):
        commands.append(cmd)
        if OPTION in cmd:
            if phased_output is None:
                raise pkgops.OpError("apt-get -s exited with 100\nsomething went wrong")
            return 0, phased_output
        return 0, APT_SIM

    monkeypatch.setattr(pkgops, "run", fake_run)
    return commands


def test_apt_scan_separates_phased_updates(monkeypatch):
    commands = _run(monkeypatch)
    pending, phased = pkgops.apt_scan(None, refresh=False)
    assert [p["name"] for p in pending] == ["liblzma5", "apt"]
    assert phased == ["curl", "libnss3"]
    assert not any(cmd[:2] == ["apt-get", "update"] for cmd in commands)
    assert OPTION in commands[1] and OPTION not in commands[0]


def test_apt_scan_survives_a_failed_phased_simulation(monkeypatch):
    logs = []
    _run(monkeypatch, phased_output=None)
    pending, phased = pkgops.apt_scan(logs.append, refresh=False)
    assert [p["name"] for p in pending] == ["liblzma5", "apt"]
    assert phased == []
    assert any("phased-update check unavailable" in line for line in logs)


def test_op_scan_reports_phased_without_counting_them(monkeypatch):
    _run(monkeypatch)
    logs = []
    monkeypatch.setattr(pkgops, "family", lambda: "apt")
    monkeypatch.setattr(pkgops, "facts", lambda: {"os_id": "ubuntu"})
    monkeypatch.setattr(pkgops, "apt_reboot_required", lambda: False)
    monkeypatch.setattr(pkgops, "apt_holds", lambda: [])
    monkeypatch.setattr(pkgops, "auto_updates", lambda fam: [])

    result = pkgops.op_scan(logs.append, refresh=False)
    assert result["phased_updates"] == ["curl", "libnss3"]
    assert result["pending_count"] == 2 and result["security_count"] == 1
    assert not any(p["name"] in result["phased_updates"] for p in result["pending"])
    assert any("held back by Ubuntu phasing" in line for line in logs)


def test_op_scan_on_dnf_has_no_phased_updates(monkeypatch):
    monkeypatch.setattr(pkgops, "family", lambda: "dnf")
    monkeypatch.setattr(pkgops, "facts", lambda: {})
    monkeypatch.setattr(pkgops, "dnf_scan", lambda log, refresh: [])
    monkeypatch.setattr(pkgops, "dnf_reboot_required", lambda: False)
    monkeypatch.setattr(pkgops, "dnf_holds", lambda: [])
    monkeypatch.setattr(pkgops, "auto_updates", lambda fam: [])
    assert pkgops.op_scan(lambda line: None, refresh=False)["phased_updates"] == []


class RecordingConn:
    def __init__(self):
        self.statements = []

    async def execute(self, sql, *args):
        self.statements.append((sql, args))


def _record(result: dict, monkeypatch) -> RecordingConn:
    """Run a scan's persistence with a fake database; no pending updates, so no cursor."""
    conn = RecordingConn()

    @asynccontextmanager
    async def transaction():
        yield conn

    async def no_rows(*_args):
        return []

    monkeypatch.setattr(fleet.db, "transaction", transaction)
    monkeypatch.setattr(fleet.db, "fetch", no_rows)
    asyncio.run(fleet.record_scan(7, {"pending": [], **result}))
    return conn


def _phased_written(conn: RecordingConn) -> list:
    return [arg for sql, params in conn.statements if "phased_updates" in sql for arg in params]


def test_phased_updates_column_is_in_the_schema():
    schema = (ROOT / "fleetwright" / "schema.sql").read_text()
    assert "ALTER TABLE hosts ADD COLUMN IF NOT EXISTS phased_updates TEXT[]" in schema


def test_record_scan_persists_phased_updates(monkeypatch):
    conn = _record({"phased_updates": ["curl", "libnss3"]}, monkeypatch)
    assert _phased_written(conn) == [(["curl", "libnss3"], 7)]


def test_record_scan_clears_phased_updates_when_empty_or_null(monkeypatch):
    assert _phased_written(_record({"phased_updates": []}, monkeypatch)) == [([], 7)]
    assert _phased_written(_record({"phased_updates": None}, monkeypatch)) == [([], 7)]


def test_record_scan_keeps_last_phased_updates_when_an_old_agent_omits_them(monkeypatch):
    assert _phased_written(_record({"auto_updates": []}, monkeypatch)) == []


def _request():
    return Request({"type": "http", "method": "GET", "path": "/hosts/1", "query_string": b"",
                    "headers": [], "scheme": "http", "server": ("testserver", 80)})


def _host(**changes):
    h = dict(id=1, name="web1", address="10.0.0.1", port=22, mode="ssh", group_id=None,
             group_name=None, tags=[], os_pretty="Ubuntu 24.04", kernel=None, key_user="root",
             key_name="key", credential_id=None, ssh_host_key=None, held=[],
             auto_updates=[], created_at=None, booted_at=None, last_scan_at=None,
             reboot_required=False, pending_count=0, security_count=0, os_holds=[],
             phased_updates=[])
    h.update(changes)
    return h


def _page(h: dict) -> str:
    return templates.env.get_template("host.html").render(
        request=_request(), current_user={"id": 1, "name": "Vic", "role": "viewer"},
        csrf="", flashes=[], h=h, server_agent={"bundle": "abc", "version": "0.3.0"},
        twins=[], pending=[], counts={"all": 0, "security": 0, "kernel": 0, "held": 0},
        kind="all", new_pkgs=0, history=[], changes=[], active_task=None, policies=[],
        groups=[], keys=[])


def test_host_page_shows_phased_updates():
    html = _page(_host(phased_updates=["curl", "libnss3"],
                       last_scan_at=datetime(2026, 11, 27, 8, tzinfo=timezone.utc)))
    assert "Ubuntu phased updates" in html
    assert "curl" in html and "libnss3" in html
    assert "Held back by Ubuntu phasing" in html
    assert "will appear automatically as phasing progresses" in html


def test_host_page_says_none_when_there_are_no_phased_updates():
    html = _page(_host(last_scan_at=datetime(2026, 11, 27, 8, tzinfo=timezone.utc))).lower()
    assert "ubuntu phased updates" in html
    assert "none reported in the last scan" in html
    assert "not scanned yet" not in html


def test_host_page_tolerates_a_host_without_the_new_field():
    h = _host()
    h.pop("phased_updates")
    assert "Ubuntu phased updates" in _page(h)
