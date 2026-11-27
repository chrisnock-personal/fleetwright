"""Certificate changes: which agents may be stuck on the old pin, and the command to re-enrol them."""

import asyncio
import html
import importlib.util
import sys
from datetime import datetime, timezone
from types import SimpleNamespace

from fleetwright import gateway, pkgops, tls
from fleetwright.actions import admin
from fleetwright.webcommon import templates

PIN = "current-pin"
OLD = "old-pin"
SEEN = datetime(2026, 11, 26, 8, 0, tzinfo=timezone.utc)


def _host(name, pin, connected=False, seen=SEEN):
    return {"id": 1, "name": name, "agent_connected": connected, "last_seen": seen, "agent_tls_pin": pin}


def test_host_on_current_pin_is_not_flagged():
    rows = [_host("web-current", PIN, connected=True), _host("web-old", OLD), _host("web-unknown", None)]
    assert [h["name"] for h in admin.cert_change_hosts(rows, PIN)] == ["web-old", "web-unknown"]


def test_offline_host_on_old_pin_is_flagged():
    rows = [_host("web-old", OLD)]
    assert admin.cert_change_hosts(rows, PIN) == [
        {"id": 1, "name": "web-old", "connected": False, "last_seen": SEEN, "pin": OLD, "state": "old_pin"}]


def test_a_missing_pin_is_labelled_unknown_not_old():
    flagged = admin.cert_change_hosts([_host("web-unknown", None)], PIN)
    assert len(flagged) == 1
    assert flagged[0]["state"] == "unknown" and flagged[0]["pin"] is None


def test_no_comparison_without_a_served_certificate():
    assert admin.cert_change_hosts([_host("web-old", OLD)], "") == []


def test_install_command_pins_the_current_certificate(monkeypatch):
    monkeypatch.setattr(gateway.config, "PUBLIC_URL", "https://fw.example:8443")
    monkeypatch.setattr(gateway, "server_pin", lambda: "PIN")
    assert gateway.install_command("tok-123") == (
        "curl -fsSL -k --pinnedpubkey 'sha256//PIN' https://fw.example:8443/agent/install.sh "
        "| sudo sh -s -- tok-123")


def test_only_the_current_pin_is_recorded(monkeypatch):
    calls = []

    async def execute(sql, *args):
        calls.append((sql, args))

    monkeypatch.setattr(gateway.db, "execute", execute)
    monkeypatch.setattr(gateway, "server_pin", lambda: PIN)
    asyncio.run(gateway.record_pin(7, OLD))       # a late acknowledgement of the old certificate
    assert calls == []
    asyncio.run(gateway.record_pin(7, PIN))
    assert len(calls) == 1 and calls[0][1] == (PIN, 7)
    assert "agent_tls_pin" in calls[0][0]


def test_agent_acknowledges_the_certificate_it_just_trusted(tmp_path, monkeypatch):
    spec = importlib.util.spec_from_file_location("fleetwright_agent_cert_test",
                                                  gateway.AGENT_FILES["fleetwright_agent.py"])
    agent = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(agent)
    monkeypatch.setitem(sys.modules, "pkgops", pkgops)
    monkeypatch.setattr(tls.config, "TLS_DIR", str(tmp_path))
    monkeypatch.setattr(tls.config, "PUBLIC_URL", "https://fw.example:8443")
    tls.generate_self_signed()
    pem = tls.leaf_pem()
    cfg = {"trust": []}
    conn = agent.Agent(cfg)
    sent = []

    async def send(msg):
        sent.append(msg)

    monkeypatch.setattr(conn, "send", send)
    monkeypatch.setattr(agent, "save_config", lambda _cfg: None)
    asyncio.run(conn.add_trust(pem, PIN))
    assert cfg["trust"] == [pem]
    assert sent == [{"type": "trust_ack", "pin": PIN}]


def _page(reenrol, command, template_command):
    info = tls.CertInfo(subject="CN=fw.example", issuer="CN=fw.example", names=["fw.example"],
                        not_after=SEEN, self_signed=True, sha256="AA:BB", spki_pin=PIN, pem="")
    return templates.env.get_template("settings_https.html").render(
        request=SimpleNamespace(query_params={}), current_user=None, csrf="", flashes=[], section="https",
        tls_on=True, info=info, public_url="https://fw.example:8443", agents=1, error=None, restarting=False,
        reenrol=reenrol, reenrol_command=command, command_template=template_command)


def test_https_page_renders_hosts_and_the_re_enrol_command(monkeypatch):
    monkeypatch.setattr(gateway.config, "PUBLIC_URL", "https://fw.example:8443")
    monkeypatch.setattr(gateway, "server_pin", lambda: "PIN")
    command = gateway.install_command("tok-123")
    rows = [_host("web-current", PIN, connected=True), _host("web-old", OLD), _host("web-unknown", None)]
    reenrol = {"available": True, "pin": PIN, "hosts": admin.cert_change_hosts(rows, PIN)}
    page = _page(reenrol, command, gateway.install_command("<enrolment token>"))

    assert "web-old" in page and "web-unknown" in page
    assert "web-current" not in page
    assert "Old pin" in page and "Unknown pin" in page
    assert command in html.unescape(page)


def test_https_page_offers_to_create_a_token(monkeypatch):
    monkeypatch.setattr(gateway.config, "PUBLIC_URL", "https://fw.example:8443")
    monkeypatch.setattr(gateway, "server_pin", lambda: "PIN")
    reenrol = {"available": True, "pin": PIN, "hosts": []}
    page = _page(reenrol, None, gateway.install_command("<enrolment token>"))

    assert "Create a re-enrol token" in page
    assert "&lt;enrolment token&gt;" in page
