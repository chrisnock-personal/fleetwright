"""Agent self-update: the agent and server agree on the bundle id, and an update
replaces nothing unless every file matches the SHA-256 the server announced."""

import hashlib
import importlib.util
import io
import sys

import pytest

from fleetwright import gateway, pkgops

sys.modules.setdefault("pkgops", pkgops)   # what the agent imports, installed beside it
_spec = importlib.util.spec_from_file_location("fleetwright_agent", gateway.AGENT_FILES["fleetwright_agent.py"])
agent = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(agent)


def test_agent_and_server_agree_on_the_bundle_id():
    b = gateway.agent_bundle()
    assert agent.bundle_id(b["files"]) == b["bundle"]
    assert b["version"] == agent.AGENT_VERSION
    assert set(b["files"]) == set(agent.BUNDLE_FILES)


@pytest.fixture
def installed(tmp_path, monkeypatch):
    for name in agent.BUNDLE_FILES:
        (tmp_path / name).write_text(f"# old {name}\n")
    monkeypatch.setattr(agent, "AGENT_DIR", str(tmp_path))
    return tmp_path


def _serve(monkeypatch, files: dict[str, bytes]):
    def urlopen(url, timeout=None, context=None):
        return io.BytesIO(files[url.rsplit("/", 1)[1]])
    monkeypatch.setattr(agent.urllib.request, "urlopen", urlopen)


def _offer(files: dict[str, bytes]) -> dict:
    hashes = {n: hashlib.sha256(d).hexdigest() for n, d in files.items()}
    return {"version": "9.9.9", "files": hashes, "bundle": agent.bundle_id(hashes)}


NEW = {"fleetwright_agent.py": b"AGENT_VERSION = '9.9.9'\n", "pkgops.py": b"VERSION = '9.9.9'\n"}
CFG = {"server": "https://fw.example:8443", "trust": []}


def test_update_replaces_both_files(installed, monkeypatch):
    _serve(monkeypatch, NEW)
    result = agent.self_update(CFG, _offer(NEW), lambda _l: None)
    assert result["restarting"] and result["version"] == "9.9.9"
    for name, data in NEW.items():
        assert (installed / name).read_bytes() == data
    assert agent.own_bundle() == _offer(NEW)["bundle"]
    assert not list(installed.glob("*.new"))


def test_a_mismatched_file_replaces_nothing(installed, monkeypatch):
    offer = _offer(NEW)
    _serve(monkeypatch, dict(NEW, **{"pkgops.py": b"something else\n"}))
    with pytest.raises(pkgops.OpError, match="doesn't match"):
        agent.self_update(CFG, offer, lambda _l: None)
    for name in agent.BUNDLE_FILES:
        assert (installed / name).read_text() == f"# old {name}\n"
    assert not list(installed.glob("*.new"))


def test_an_agent_file_that_cant_run_replaces_nothing(installed, monkeypatch):
    broken = dict(NEW, **{"fleetwright_agent.py": b"def (:\n"})
    _serve(monkeypatch, broken)
    with pytest.raises(SyntaxError):
        agent.self_update(CFG, _offer(broken), lambda _l: None)
    assert (installed / "fleetwright_agent.py").read_text() == "# old fleetwright_agent.py\n"


def test_unexpected_file_names_are_refused(installed, monkeypatch):
    offer = _offer(dict(NEW, **{"../../etc/passwd": b"x"}))
    with pytest.raises(pkgops.OpError, match="unexpected file list"):
        agent.self_update(CFG, offer, lambda _l: None)


def test_already_current_does_nothing(installed, monkeypatch):
    current = {n: (installed / n).read_bytes() for n in agent.BUNDLE_FILES}
    result = agent.self_update(CFG, _offer(current), lambda _l: None)
    assert result == {"ok": True, "restarting": False}
