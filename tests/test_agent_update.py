"""Agent self-update: the agent and server agree on the bundle id, an update
replaces nothing unless every file matches the SHA-256 the server announced,
and the wrapper rolls back if the new agent never connects."""

import asyncio
import hashlib
import importlib.util
import io
import os
import stat
import subprocess
import sys
import time
import uuid

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


def test_update_keeps_the_previous_files_for_the_wrapper(installed, monkeypatch):
    _serve(monkeypatch, NEW)
    agent.self_update(CFG, _offer(NEW), lambda _l: None)
    for name in agent.BUNDLE_FILES:
        prev = installed / (name + ".prev")
        assert prev.read_bytes() == f"# old {name}\n".encode()
        assert stat.S_IMODE(prev.stat().st_mode) == 0o644
    assert not list(installed.glob("*.tmp"))


def test_backup_files_are_not_part_of_the_bundle(installed, monkeypatch):
    _serve(monkeypatch, NEW)
    agent.self_update(CFG, _offer(NEW), lambda _l: None)
    assert set(agent.BUNDLE_FILES) == {"fleetwright_agent.py", "pkgops.py"}
    assert agent.own_bundle() == _offer(NEW)["bundle"]
    assert list(installed.glob("*.prev"))


def test_a_mismatched_file_replaces_nothing(installed, monkeypatch):
    offer = _offer(NEW)
    _serve(monkeypatch, dict(NEW, **{"pkgops.py": b"something else\n"}))
    with pytest.raises(pkgops.OpError, match="doesn't match"):
        agent.self_update(CFG, offer, lambda _l: None)
    for name in agent.BUNDLE_FILES:
        assert (installed / name).read_text() == f"# old {name}\n"
    assert not list(installed.glob("*.new"))
    assert not list(installed.glob("*.prev"))


def test_an_agent_file_that_cant_run_replaces_nothing(installed, monkeypatch):
    broken = dict(NEW, **{"fleetwright_agent.py": b"def (:\n"})
    _serve(monkeypatch, broken)
    with pytest.raises(SyntaxError):
        agent.self_update(CFG, _offer(broken), lambda _l: None)
    assert (installed / "fleetwright_agent.py").read_text() == "# old fleetwright_agent.py\n"
    assert not list(installed.glob("*.prev"))


def test_unexpected_file_names_are_refused(installed, monkeypatch):
    offer = _offer(dict(NEW, **{"../../etc/passwd": b"x"}))
    with pytest.raises(pkgops.OpError, match="unexpected file list"):
        agent.self_update(CFG, offer, lambda _l: None)


def test_already_current_does_nothing(installed, monkeypatch):
    current = {n: (installed / n).read_bytes() for n in agent.BUNDLE_FILES}
    result = agent.self_update(CFG, _offer(current), lambda _l: None)
    assert result == {"ok": True, "restarting": False}


# ─── The connected marker, watched by the wrapper ──────────────────────────

def test_marker_helper_writes_a_nonempty_marker(tmp_path, monkeypatch):
    monkeypatch.delenv("FLEETWRIGHT_AGENT_CONNECTED_MARKER", raising=False)
    monkeypatch.delenv("FLEETWRIGHT_AGENT_MARKER", raising=False)
    marker = tmp_path / "run" / "connected"
    monkeypatch.setattr(agent, "CONNECTED_MARKER", str(marker))
    agent.mark_connected()
    assert marker.read_bytes().strip()
    assert stat.S_IMODE(marker.stat().st_mode) == 0o644
    assert not list(tmp_path.glob("**/*.tmp"))


def test_marker_helper_honours_an_environment_override(tmp_path, monkeypatch):
    other = tmp_path / "elsewhere" / "connected"
    monkeypatch.setenv("FLEETWRIGHT_AGENT_CONNECTED_MARKER", str(other))
    agent.mark_connected()
    assert other.exists()
    assert other.read_bytes().strip()


class _FakeWS:
    def __init__(self):
        self.sent: list[str] = []
        self.incoming = ['{"type": "welcome", "scan_interval_min": 1}']

    async def send(self, text: str) -> None:
        self.sent.append(text)

    def __aiter__(self):
        return self

    async def __anext__(self):
        if self.incoming:
            return self.incoming.pop(0)
        raise StopAsyncIteration


def test_session_marks_connected_after_saying_hello(monkeypatch):
    ws = _FakeWS()

    async def connect(cfg):
        return ws

    calls = []
    monkeypatch.setattr(agent, "ws_connect", connect)
    monkeypatch.setattr(agent, "own_bundle", lambda: "a-bundle")
    monkeypatch.setattr(agent, "host_facts", lambda _server: {})
    monkeypatch.setattr(agent, "mark_connected", lambda: calls.append("connected"))
    asyncio.run(agent.Agent(dict(CFG, token="t")).session())
    assert calls == ["connected"]
    assert '"type": "hello"' in ws.sent[0]


def test_a_failed_first_connection_does_not_mark_connected(monkeypatch):
    async def connect(cfg):
        raise RuntimeError("no server")

    calls = []
    monkeypatch.setattr(agent, "ws_connect", connect)
    monkeypatch.setattr(agent, "mark_connected", lambda: calls.append("connected"))
    with pytest.raises(RuntimeError, match="no server"):
        asyncio.run(agent.Agent(dict(CFG, token="t")).session())
    assert calls == []


# ─── The wrapper restores a new agent that never connects ──────────────────

WRAPPER = gateway.AGENT_DIR / "fleetwright-agent-wrapper.sh"


def _install_files(directory, version):
    for name in agent.BUNDLE_FILES:
        (directory / name).write_text(f"# {version} {name}\n")


def _fake_agent(path, marker, directory, behaviour):
    """A stand-in for /usr/bin/python3 <agent> run; it never imports the agent."""
    path.write_text(f'''#!/usr/bin/env python3
import os
import sys
import time

marker = {str(marker)!r}
directory = {str(directory)!r}
behaviour = {behaviour!r}

if behaviour in ("connect", "connect_exit", "after_restore"):
    if behaviour == "after_restore":
        with open(os.path.join(directory, "fleetwright_agent.py")) as f:
            if not f.read().startswith("# old"):
                while True:
                    time.sleep(0.02)
    with open(marker, "w") as f:
        f.write("connected\\n")
    if behaviour == "connect_exit":
        sys.exit(0)
while True:
    time.sleep(0.02)
''')
    path.chmod(0o755)


def _wrapper_env(tmp_path, marker, fake, max_exits="2"):
    return dict(os.environ,
                FLEETWRIGHT_AGENT_DIR=str(tmp_path),
                FLEETWRIGHT_AGENT_PYTHON=str(fake),
                FLEETWRIGHT_AGENT_CONNECTED_MARKER=str(marker),
                FLEETWRIGHT_AGENT_CONNECT_TIMEOUT="0.3",
                FLEETWRIGHT_AGENT_CHECK_INTERVAL="0.02",
                FLEETWRIGHT_AGENT_MAX_EXITS=max_exits,
                FLEETWRIGHT_AGENT_RESTART_DELAY="0.02")


def _wait_for(predicate, timeout=5):
    until = time.monotonic() + timeout
    while time.monotonic() < until:
        if predicate():
            return True
        time.sleep(0.02)
    return False


def _stop(proc):
    if proc.poll() is None:
        proc.terminate()
        try:
            proc.wait(timeout=3)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=3)


def _run_wrapper(env):
    return subprocess.Popen([str(WRAPPER)], env=env,
                            stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)


def test_wrapper_restores_and_restarts_when_no_marker_appears(tmp_path):
    _install_files(tmp_path, "new")
    for name in agent.BUNDLE_FILES:
        (tmp_path / (name + ".prev")).write_text(f"# old {name}\n")
    marker = tmp_path / "run" / "connected"
    fake = tmp_path / "fake-python"
    _fake_agent(fake, marker, tmp_path, "after_restore")
    proc = _run_wrapper(_wrapper_env(tmp_path, marker, fake))
    try:
        connected = lambda: marker.exists() and marker.stat().st_size > 0  # noqa: E731
        assert _wait_for(lambda: (tmp_path / "fleetwright_agent.py").read_text()
                         == "# old fleetwright_agent.py\n" and connected())
        for name in agent.BUNDLE_FILES:
            assert (tmp_path / name).read_bytes() == (tmp_path / (name + ".prev")).read_bytes()
            assert stat.S_IMODE((tmp_path / name).stat().st_mode) == 0o644
    finally:
        _stop(proc)


def test_wrapper_does_not_restore_when_the_agent_connects(tmp_path):
    _install_files(tmp_path, "new")
    for name in agent.BUNDLE_FILES:
        (tmp_path / (name + ".prev")).write_text(f"# old {name}\n")
    marker = tmp_path / "run" / "connected"
    fake = tmp_path / "fake-python"
    _fake_agent(fake, marker, tmp_path, "connect")
    proc = _run_wrapper(_wrapper_env(tmp_path, marker, fake))
    try:
        assert _wait_for(lambda: marker.exists() and marker.stat().st_size > 0)
        time.sleep(0.2)
        for name in agent.BUNDLE_FILES:
            assert (tmp_path / name).read_text() == f"# new {name}\n"
    finally:
        _stop(proc)


def test_wrapper_restores_after_an_agent_that_keeps_exiting(tmp_path):
    _install_files(tmp_path, "new")
    for name in agent.BUNDLE_FILES:
        (tmp_path / (name + ".prev")).write_text(f"# old {name}\n")
    marker = tmp_path / "run" / "connected"
    fake = tmp_path / "fake-python"
    _fake_agent(fake, marker, tmp_path, "connect_exit")
    proc = _run_wrapper(_wrapper_env(tmp_path, marker, fake))
    try:
        assert _wait_for(lambda: (tmp_path / "fleetwright_agent.py").read_text()
                         == "# old fleetwright_agent.py\n")
    finally:
        _stop(proc)


def test_wrapper_gives_up_without_a_previous_agent(tmp_path):
    _install_files(tmp_path, "new")
    marker = tmp_path / "run" / "connected"
    fake = tmp_path / "fake-python"
    _fake_agent(fake, marker, tmp_path, "no_connect")
    proc = _run_wrapper(_wrapper_env(tmp_path, marker, fake))
    assert proc.wait(timeout=5) == 0
    assert b"no previous files" in proc.stderr.read()
    for name in agent.BUNDLE_FILES:
        assert (tmp_path / name).read_text() == f"# new {name}\n"


# ─── Deployment and the server's view of a rollback ────────────────────────

def test_systemd_starts_the_wrapper():
    service = (gateway.AGENT_DIR / "fleetwright-agent.service").read_text()
    exec_lines = [line for line in service.splitlines() if line.startswith("ExecStart=")]
    assert exec_lines == ["ExecStart=/opt/fleetwright-agent/fleetwright-agent-wrapper.sh"]
    assert "Restart=always" in service


def test_gateway_serves_the_wrapper_and_installer_uses_it():
    assert gateway.AGENT_FILES["fleetwright-agent-wrapper.sh"].exists()
    assert "fleetwright-agent-wrapper.sh" not in agent.BUNDLE_FILES
    install = (gateway.AGENT_DIR / "install.sh").read_text()
    assert 'fetch "$SERVER/agent/files/fleetwright-agent-wrapper.sh"' in install


def test_a_changed_bundle_after_an_update_is_reported_as_a_rollback(monkeypatch):
    task = {"id": 3, "host_id": 7, "result": {"bundle": "the-new-bundle"}}

    async def fetch(*args):
        return [task]

    async def execute(*args):
        return 1

    logs, finished = [], []

    async def append_log(task_id, text):
        logs.append((task_id, text))

    async def finish_task(task_id, ok, text):
        finished.append((task_id, ok, text))

    monkeypatch.setattr(gateway.db, "fetch", fetch)
    monkeypatch.setattr(gateway.db, "execute", execute)
    monkeypatch.setattr(gateway.fleet, "append_log", append_log)
    monkeypatch.setattr(gateway.fleet, "finish_task", finish_task)
    asyncio.run(gateway.finish_agent_updates(7, "0.3.1", "the-old-bundle"))
    assert finished == [(3, False, "The agent rolled back to 0.3.1")]
    assert "rolled back" in logs[0][1]


# ─── The agent's own instance id ────────────────────────────────────────────

def test_instance_id_is_created_once_and_reused(tmp_path, monkeypatch):
    path = tmp_path / "fleetwright-agent" / "instance-id"
    monkeypatch.setattr(pkgops, "INSTANCE_ID_PATH", str(path))
    first = pkgops.instance_id()
    assert uuid.UUID(first)
    assert path.read_text().strip() == first
    assert pkgops.instance_id() == first
    path.write_text("not an id\n")            # a damaged file is replaced
    assert pkgops.instance_id() != first


def test_facts_carry_the_instance_id(monkeypatch):
    monkeypatch.setattr(pkgops, "instance_id", lambda: "an-instance-id")
    monkeypatch.setattr(pkgops, "family", lambda: "apt")
    assert pkgops.facts()["instance_id"] == "an-instance-id"


# ─── Telling a reinstall from a cloned machine ─────────────────────────────

def _host(i, name, boot, connected, hostname=None, instance=None):
    return {"id": i, "name": name, "boot_id": boot, "agent_connected": connected,
            "hostname": hostname, "instance_id": instance}


def test_reinstall_on_the_running_machine_keeps_its_host():
    # install.sh enrols while the old agent is still connected, from the same boot
    web1 = _host(1, "web1", "boot-a", True, "web1")
    assert gateway.same_machine({"boot_id": "boot-a"}, "web1", [web1]) is web1


def test_reinstall_after_a_reboot_with_the_old_agent_offline_keeps_its_host():
    web1 = _host(1, "web1", "boot-a", False, "web1")
    assert gateway.same_machine({"boot_id": "boot-b"}, "web1", [web1]) is web1
    renamed = _host(1, "frontend-1", "boot-a", False, "web1")   # renamed in FleetWright
    assert gateway.same_machine({"boot_id": "boot-b"}, "web1", [renamed]) is renamed


def test_a_clone_gets_a_host_of_its_own():
    original = _host(1, "web1", "boot-a", True, "web1")
    # live original: even the same hostname doesn't make it the same machine
    assert gateway.same_machine({"boot_id": "boot-c"}, "web1", [original]) is None
    offline = _host(1, "web1", "boot-a", False, "web1")
    assert gateway.same_machine({"boot_id": "boot-c"}, "web2", [offline]) is None


def test_containers_sharing_a_kernel_and_a_machine_id_stay_apart():
    # every container on one kernel reports the same boot id
    web1 = _host(1, "web1", "kernel-boot", True, "web1")
    assert gateway.same_machine({"boot_id": "kernel-boot"}, "web2", [web1]) is None


def test_a_different_instance_id_never_takes_over_the_same_host():
    # identical machine id, hostname and kernel boot id: only the instance id differs
    web1 = _host(1, "web1", "kernel-boot", True, "web1", "instance-1")
    assert gateway.same_machine({"boot_id": "kernel-boot", "instance_id": "instance-2"},
                                "web1", [web1]) is None
    # an agent upgraded on a host with no id yet still matches the old checks
    old = _host(2, "web2", "kernel-boot", True, "web2")
    assert gateway.same_machine({"boot_id": "kernel-boot", "instance_id": "instance-2"},
                                "web2", [old]) is old


def test_the_same_instance_id_keeps_its_host_even_if_the_machine_id_changed():
    web1 = _host(1, "web1", "boot-a", True, "web1", "instance-1")
    assert gateway.same_machine({"boot_id": "boot-b", "instance_id": "instance-1"},
                                "web1", [web1]) is web1


def test_a_reinstall_on_the_second_of_two_clones_finds_the_right_one():
    a = _host(1, "web1", "boot-a", True, "web1")
    b = _host(2, "web2", "boot-b", True, "web2")
    assert gateway.same_machine({"boot_id": "boot-b"}, "web2", [a, b]) is b


def test_two_machines_sharing_one_identity():
    assert gateway.shared_identity([("a", 0), ("b", 5), ("a", 10)])
    assert not gateway.shared_identity([("a", 0), ("b", 5)])                 # a reboot
    assert not gateway.shared_identity([("a", 0), ("a", 5), ("a", 10)])      # reconnects
    assert not gateway.shared_identity([("a", 0), ("b", 5), ("c", 10)])      # reboots
    assert not gateway.shared_identity([("a", 0), ("b", 5), ("a", 4000)])    # too far apart
