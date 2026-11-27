"""OS-level package holds (apt-mark / dnf versionlock): scan results reach the host row
and the host page, without changing FleetWright's own "never install" list."""

import asyncio
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from pathlib import Path

from starlette.requests import Request

from fleetwright import fleet
from fleetwright.webcommon import templates

ROOT = Path(__file__).resolve().parent.parent


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


def _holds_written(conn: RecordingConn) -> list:
    return [arg for sql, params in conn.statements if "os_holds" in sql for arg in params]


def test_os_holds_column_is_in_the_schema():
    schema = (ROOT / "fleetwright" / "schema.sql").read_text()
    assert "ALTER TABLE hosts ADD COLUMN IF NOT EXISTS os_holds TEXT[]" in schema


def test_record_scan_persists_os_holds(monkeypatch):
    conn = _record({"os_holds": ["nginx", "postgresql-16"]}, monkeypatch)
    assert _holds_written(conn) == [(["nginx", "postgresql-16"], 7)]


def test_record_scan_clears_os_holds_when_empty_or_null(monkeypatch):
    assert _holds_written(_record({"os_holds": []}, monkeypatch)) == [([], 7)]
    assert _holds_written(_record({"os_holds": None}, monkeypatch)) == [([], 7)]


def test_record_scan_keeps_the_last_holds_when_an_old_agent_omits_them(monkeypatch):
    assert _holds_written(_record({"auto_updates": []}, monkeypatch)) == []


def _request():
    return Request({"type": "http", "method": "GET", "path": "/hosts/1", "query_string": b"",
                    "headers": [], "scheme": "http", "server": ("testserver", 80)})


def _host(**changes):
    h = dict(id=1, name="web1", address="10.0.0.1", port=22, mode="ssh", group_id=None,
             group_name=None, tags=[], os_pretty="Ubuntu 24.04", kernel=None, key_user="root",
             key_name="key", credential_id=None, ssh_host_key=None, held=["old-pkg"],
             auto_updates=[], created_at=None, booted_at=None, last_scan_at=None,
             reboot_required=False, pending_count=0, security_count=0, os_holds=[])
    h.update(changes)
    return h


def _page(h: dict) -> str:
    return templates.env.get_template("host.html").render(
        request=_request(), current_user={"id": 1, "name": "Vic", "role": "viewer"},
        csrf="", flashes=[], h=h, server_agent={"bundle": "abc", "version": "0.3.0"},
        twins=[], pending=[], counts={"all": 0, "security": 0, "kernel": 0, "held": 0},
        kind="all", new_pkgs=0, history=[], changes=[], active_task=None, policies=[],
        groups=[], keys=[])


def test_host_page_shows_os_holds():
    html = _page(_host(os_holds=["nginx", "postgresql-16"], last_scan_at=datetime(2026, 11, 26, 8, tzinfo=timezone.utc)))
    assert "OS-level holds" in html
    assert "nginx" in html and "postgresql-16" in html
    assert "apt-mark / dnf versionlock" in html


def test_host_page_says_none_when_there_are_no_holds():
    html = _page(_host(last_scan_at=datetime(2026, 11, 26, 8, tzinfo=timezone.utc))).lower()
    assert "os-level holds" in html
    assert "none reported in the last scan" in html
    assert "not scanned yet" not in html


def test_host_page_tolerates_a_host_without_the_new_field():
    h = _host()
    h.pop("os_holds")
    assert "OS-level holds" in _page(h)
