"""fw, the command-line client: parsing, output, exit codes and completion, against a
small fake API (the real API is tested in tests/integration)."""

import json
import subprocess
import sys
import threading
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "cli"))
from fleetwright_cli import main as fw  # noqa: E402
from fleetwright_cli.client import CLIError  # noqa: E402
from fleetwright_cli.complete import script  # noqa: E402

HOSTS = [{"id": 1, "name": "web-01", "group_name": "web", "os_pretty": "Ubuntu 24.04", "pending_count": 3,
          "security_count": 1, "reboot_required": False, "mode": "ssh", "last_scan_at": "2026-11-24T10:00:00Z"},
         {"id": 2, "name": "web-02", "group_name": "web", "os_pretty": "Ubuntu 24.04", "pending_count": 0,
          "security_count": 0, "reboot_required": True, "mode": "agent", "last_scan_at": None}]
SEEN = []


class FakeAPI(BaseHTTPRequestHandler):
    def _send(self, status, body):
        data = json.dumps(body).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        SEEN.append(("GET", self.path, self.headers.get("Authorization")))
        if self.headers.get("Authorization") != "Bearer fwt_good":
            return self._send(401, {"error": {"code": "unauthorized", "message": "Send a valid API token"}})
        if self.path == "/api/v1/me":
            return self._send(200, {"user_id": 1, "name": "Sam", "role": "viewer", "token_id": 3,
                                    "token_name": "ci"})
        if self.path.startswith("/api/v1/hosts?"):
            return self._send(200, {"hosts": HOSTS, "counts": {}, "total": 2, "next_cursor": None})
        if self.path.startswith("/api/v1/hosts/2/updates"):
            return self._send(200, {"updates": [{"name": "openssl", "current": "3.0.1", "available": "3.0.2",
                                                 "kind": "security", "severity": None, "is_kernel": False,
                                                 "held": False, "advisory": None}], "counts": {}})
        return self._send(404, {"error": {"code": "not_found", "message": "No such thing"}})

    def do_POST(self):
        body = json.loads(self.rfile.read(int(self.headers["Content-Length"])) or b"{}")
        SEEN.append(("POST", self.path, body, self.headers.get("Idempotency-Key")))
        if self.path == "/api/v1/runs":
            return self._send(403, {"error": {"code": "forbidden", "message": "This needs the Operator role."}})
        if self.path == "/api/v1/policies/preview":
            return self._send(200, {"hosts": 2, "updates": 5, "affected": 1, "reboot_hosts": 0})
        return self._send(404, {"error": {"code": "not_found", "message": "No such thing"}})

    def log_message(self, *a):
        pass


@pytest.fixture
def server(monkeypatch, tmp_path):
    srv = HTTPServer(("127.0.0.1", 0), FakeAPI)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    monkeypatch.setenv("FW_URL", f"http://127.0.0.1:{srv.server_port}")
    monkeypatch.setenv("FW_TOKEN", "fwt_good")
    monkeypatch.setattr(fw, "load_config", lambda: {"default": None, "profiles": {}})
    SEEN.clear()
    yield srv
    srv.shutdown()


def run(capsys, *argv):
    code = fw.main(list(argv))
    out = capsys.readouterr()
    return code, out.out, out.err


def test_table_and_json(server, capsys):
    code, out, _ = run(capsys, "hosts", "list")
    assert code == 0 and "web-01" in out and out.splitlines()[0].startswith("ID")
    code, out, _ = run(capsys, "hosts", "list", "--json")
    assert code == 0 and [h["name"] for h in json.loads(out)["hosts"]] == ["web-01", "web-02"]
    code, out, _ = run(capsys, "hosts", "list", "--jsonl")
    assert [json.loads(line)["id"] for line in out.splitlines()] == [1, 2]


def test_exit_codes(server, capsys, monkeypatch):
    assert run(capsys, "whoami")[0] == 0
    code, _, err = run(capsys, "hosts", "show", "nope")
    assert code == 4 and "No such host: nope" in err
    code, _, err = run(capsys, "run", "apply", "web-01", "--yes")
    assert code == 3 and "Operator" in err
    assert run(capsys, "run", "apply")[0] == 2                       # no hosts named
    assert run(capsys, "hosts", "list", "--status", "bogus")[0] == 2  # argparse
    monkeypatch.setenv("FW_TOKEN", "fwt_bad")
    assert run(capsys, "whoami")[0] == 3


def test_names_become_ids_and_runs_carry_an_idempotency_key(server, capsys):
    run(capsys, "run", "apply", "web-02", "--kinds", "security", "--batch", "10%", "--canary",
        "--reboot", "if-needed", "--yes")
    method, path, body, key = SEEN[-1]
    assert (method, path) == ("POST", "/api/v1/runs")
    assert body["target"]["hosts"] == [2] and body["selection"]["kinds"] == ["security"]
    assert body["batch_percent"] == 10 and body["canary"] and body["reboot"] == "if_needed"
    assert key and len(key) >= 32


def test_changes_need_yes_when_not_interactive(server, capsys, monkeypatch):
    monkeypatch.setattr("sys.stdin.isatty", lambda: False)
    code, _, err = run(capsys, "run", "reboot", "web-01")
    assert code == 2 and "--yes" in err
    assert not any(s[1] == "/api/v1/runs" for s in SEEN)


def test_dry_run_starts_nothing(server, capsys):
    code, out, _ = run(capsys, "run", "apply", "--group", "7", "--kinds", "security", "--dry-run")
    assert code == 0 and "Would install 5 updates on 1 of 2" in out
    assert not any(s[1] == "/api/v1/runs" for s in SEEN)
    code, out, _ = run(capsys, "run", "apply", "web-02", "--pick", "openssl", "--dry-run", "--json")
    assert json.loads(out)["would_install"][0]["would_install"] == "3.0.2"


def test_parsing_helpers():
    s, e = fw.parse_window("2026-11-12 22:00/23:30")
    assert (s.isoformat(), e.isoformat()) == ("2026-11-12T22:00:00+00:00", "2026-11-12T23:30:00+00:00")
    s, e = fw.parse_window("2026-11-14 23:00/02:00")
    assert e - s == timedelta(hours=3)                      # past midnight
    with pytest.raises(CLIError):
        fw.parse_window("tomorrow evening")
    assert fw.parse_batch("10%") == (0, 10) and fw.parse_batch("5") == (5, 0) and fw.parse_batch(None) == (0, 0)
    assert abs(fw.parse_since("7d") - (datetime.now(timezone.utc) - timedelta(days=7))) < timedelta(seconds=5)
    assert fw.words(["a,b", " c "]) == ["a", "b", "c"]


def test_every_command_has_help():
    root = fw.build_parser()
    from fleetwright_cli.complete import tree
    for path in tree(root):
        with pytest.raises(SystemExit) as e:
            root.parse_args([*path, "--help"])
        assert e.value.code == 0


def test_completion_scripts(tmp_path):
    parser = fw.build_parser()
    b = script(parser, "bash")
    assert "complete -F _fw fw" in b and "'run apply'" in b and "if-needed" in b
    f = tmp_path / "fw.bash"
    f.write_text(b)
    assert subprocess.run(["bash", "-n", str(f)]).returncode == 0
    assert "bashcompinit" in script(parser, "zsh")
    fish = script(parser, "fish")
    assert "-a hosts" in fish and "-l dry-run" in fish
