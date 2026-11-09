#!/usr/bin/env python3
"""
FleetWright agent.

Runs as root under systemd, keeps one WebSocket open to the FleetWright
server (it dials out; the host needs no open port), scans for updates on
its own timer and runs the operations the server sends. It runs only
pkgops operations (scan, apply, reboot), never arbitrary commands.

    fleetwright_agent.py enroll <server url> <enrolment token> [--ca server.pem] [--insecure]
    fleetwright_agent.py run
    fleetwright_agent.py scan          # one scan, printed, for checking

Needs python3 and python3-websockets (both packaged on Ubuntu and Fedora).
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import random
import ssl
import sys
import time
import urllib.error
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import pkgops  # noqa: E402

AGENT_VERSION = "0.1.0"
CONFIG_PATH = os.environ.get("FLEETWRIGHT_AGENT_CONFIG", "/etc/fleetwright-agent/agent.json")
log = logging.getLogger("fleetwright-agent")


def load_config() -> dict:
    with open(CONFIG_PATH) as f:
        return json.load(f)


def save_config(cfg: dict) -> None:
    os.makedirs(os.path.dirname(CONFIG_PATH), mode=0o700, exist_ok=True)
    tmp = CONFIG_PATH + ".tmp"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        json.dump(cfg, f)
    os.replace(tmp, CONFIG_PATH)


def tls_context(cfg: dict) -> ssl.SSLContext:
    """The system CAs plus the FleetWright certificates this agent was given."""
    ctx = ssl.create_default_context()
    for pem in cfg.get("trust") or []:
        ctx.load_verify_locations(cadata=pem)
    return ctx


def enroll(server: str, token: str, ca_file: str | None = None, insecure: bool = False) -> int:
    server = server.rstrip("/")
    if server.startswith("http://") and not insecure:
        print("Refusing to enrol over plain HTTP (the token and tasks would be readable and "
              "changeable on the network). Use https, or pass --insecure.", file=sys.stderr)
        return 1
    trust = []
    if ca_file:
        with open(ca_file) as f:
            trust.append(f.read())
    cfg = {"server": server, "trust": trust, "insecure": insecure}
    body = json.dumps({"token": token, "facts": host_facts(server)}).encode()
    req = urllib.request.Request(f"{server}/api/agent/enroll", data=body,
                                 headers={"Content-Type": "application/json"})
    try:
        ctx = tls_context(cfg) if server.startswith("https://") else None
        with urllib.request.urlopen(req, timeout=30, context=ctx) as resp:
            data = json.load(resp)
    except urllib.error.HTTPError as e:
        print(f"Enrolment refused: {e.code} {e.read().decode(errors='replace')}", file=sys.stderr)
        return 1
    except urllib.error.URLError as e:
        print(f"Can't reach {server}: {e.reason}", file=sys.stderr)
        return 1
    cfg.update(token=data["agent_token"], host_id=data["host_id"], name=data["name"])
    save_config(cfg)
    print(f"Enrolled as {data['name']} (host {data['host_id']})")
    return 0


def host_facts(server: str) -> dict:
    """pkgops facts plus the address this host uses to reach the server."""
    facts = pkgops.facts()
    try:
        import socket
        from urllib.parse import urlsplit
        u = urlsplit(server)
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect((u.hostname, u.port or 443))   # UDP: picks a route, sends nothing
            facts["address"] = s.getsockname()[0]
    except OSError:
        pass
    return facts


def ws_url(server: str) -> str:
    if server.startswith("https://"):
        return "wss://" + server[len("https://"):] + "/api/agent/ws"
    return "ws://" + server[len("http://"):] + "/api/agent/ws"


async def ws_connect(cfg: dict):
    import websockets
    url = ws_url(cfg["server"])
    if url.startswith("ws://") and not cfg.get("insecure"):
        raise RuntimeError("refusing a plain ws:// connection; enrol over https, or with --insecure")
    headers = {"Authorization": f"Bearer {cfg['token']}"}
    # The server's certificate is checked during the TLS handshake, before the token is sent.
    opts = dict(max_size=2**24, ping_interval=30, ping_timeout=60,
                ssl=tls_context(cfg) if url.startswith("wss://") else None)
    major = int(websockets.__version__.split(".")[0])
    if major >= 14:
        return await websockets.connect(url, additional_headers=headers, **opts)
    return await websockets.connect(url, extra_headers=headers, **opts)


class Agent:
    def __init__(self, cfg: dict):
        self.cfg = cfg
        self.ws = None
        self.busy = asyncio.Lock()
        self.scan_interval = 360 * 60
        self.last_scan: float | None = None  # None: never scanned
        self.loop: asyncio.AbstractEventLoop | None = None

    async def send(self, msg: dict) -> None:
        if self.ws is not None:
            await self.ws.send(json.dumps(msg))

    def _logger(self, task_id):
        """A pkgops log callback (called from a worker thread) that ships lines to the server."""
        buf: list[str] = []
        state = {"last": time.monotonic()}

        def flush():
            if buf:
                text = "".join(buf)
                buf.clear()
                asyncio.run_coroutine_threadsafe(
                    self.send({"type": "log", "task_id": task_id, "text": text}), self.loop)
            state["last"] = time.monotonic()

        def line(text: str):
            buf.append(f"{time.strftime('%H:%M:%S', time.gmtime())} {text}\n")
            if time.monotonic() - state["last"] > 1.0 or len(buf) > 200:
                flush()

        line.flush = flush
        return line

    async def run_op(self, task_id, op: str, args: dict) -> None:
        async with self.busy:
            logger = self._logger(task_id)

            def work():
                try:
                    if op == "scan":
                        return pkgops.op_scan(logger)
                    if op == "apply":
                        sel = args.get("selection") or {"mode": "all"}
                        if not isinstance(sel, dict):
                            raise pkgops.OpError("bad selection")
                        return pkgops.op_apply(sel, logger)
                    return {"ok": False, "error": f"operation {op} isn't allowed"}
                except pkgops.OpError as e:
                    return {"ok": False, "error": str(e)}
                except Exception as e:  # noqa: BLE001
                    return {"ok": False, "error": f"{type(e).__name__}: {e}"}
                finally:
                    logger.flush()

            result = await asyncio.to_thread(work)
            if op in ("scan", "apply"):
                self.last_scan = time.monotonic()
            await self.send({"type": "result", "task_id": task_id, "result": result})

    async def reboot(self, task_id) -> None:
        async with self.busy:
            log.info("rebooting at the server's request (task %s)", task_id)
            await asyncio.to_thread(pkgops.op_reboot, lambda _l: None)

    async def scheduled_scans(self) -> None:
        await asyncio.sleep(random.uniform(5, 60))  # spread a fleet's first scans out
        while True:
            due = 0.0 if self.last_scan is None else \
                self.last_scan + self.scan_interval * random.uniform(0.9, 1.1)
            if time.monotonic() >= due and not self.busy.locked():
                async with self.busy:
                    result = await asyncio.to_thread(self._quiet_scan)
                    self.last_scan = time.monotonic()
                try:
                    await self.send({"type": "inventory", "result": result})
                except Exception:  # noqa: BLE001 - sent again next time
                    self.last_scan = None
            await asyncio.sleep(30)

    @staticmethod
    def _quiet_scan() -> dict:
        try:
            return pkgops.op_scan(lambda _l: None)
        except Exception as e:  # noqa: BLE001
            return {"ok": False, "error": str(e)}

    def add_trust(self, pem: str) -> None:
        """Remember a certificate the server sent over the already-verified connection,
        so the agent still connects after the server's certificate is replaced."""
        if "BEGIN CERTIFICATE" not in pem or pem in (self.cfg.get("trust") or []):
            return
        try:
            ssl.create_default_context().load_verify_locations(cadata=pem)
        except (ssl.SSLError, ValueError):
            log.warning("ignored an unreadable certificate from the server")
            return
        self.cfg["trust"] = ((self.cfg.get("trust") or []) + [pem])[-4:]
        save_config(self.cfg)
        log.info("now also trusting a new server certificate")

    async def session(self) -> None:
        self.ws = await ws_connect(self.cfg)
        log.info("connected to %s", self.cfg["server"])
        await self.send({"type": "hello", "version": AGENT_VERSION, "facts": host_facts(self.cfg["server"])})
        pending: set = set()
        try:
            async for raw in self.ws:
                msg = json.loads(raw)
                kind = msg.get("type")
                if kind == "welcome":
                    self.scan_interval = int(msg.get("scan_interval_min", 360)) * 60
                elif kind == "task":
                    t = asyncio.create_task(self.run_op(msg.get("task_id"), str(msg.get("op")),
                                                        msg.get("args") or {}))
                    pending.add(t)
                    t.add_done_callback(pending.discard)
                elif kind == "reboot":
                    t = asyncio.create_task(self.reboot(msg.get("task_id")))
                    pending.add(t)
                    t.add_done_callback(pending.discard)
                elif kind == "ping":
                    await self.send({"type": "pong"})
                elif kind == "trust":
                    self.add_trust(str(msg.get("pem") or ""))
        finally:
            self.ws = None

    async def main(self) -> None:
        self.loop = asyncio.get_running_loop()
        asyncio.create_task(self.scheduled_scans())
        backoff = 2
        while True:
            started = time.monotonic()
            try:
                await self.session()
            except Exception as e:  # noqa: BLE001
                code = getattr(getattr(e, "rcvd", None), "code", None) or getattr(e, "code", None)
                if code == 4401:
                    log.error("the server refused this agent's token; enrol it again")
                else:
                    log.warning("connection lost: %s", e)
            if time.monotonic() - started > 60:
                backoff = 2
            await asyncio.sleep(backoff + random.uniform(0, backoff))
            backoff = min(backoff * 2, 300)


def main(argv: list[str]) -> int:
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    if len(argv) >= 3 and argv[0] == "enroll":
        rest = argv[3:]
        ca = rest[rest.index("--ca") + 1] if "--ca" in rest and rest.index("--ca") + 1 < len(rest) else None
        return enroll(argv[1], argv[2], ca_file=ca, insecure="--insecure" in rest)
    if argv[:1] == ["scan"]:
        print(json.dumps(pkgops.op_scan(), indent=1))
        return 0
    if argv[:1] == ["run"]:
        if os.geteuid() != 0:
            print("The agent runs as root.", file=sys.stderr)
            return 1
        agent = Agent(load_config())
        asyncio.run(agent.main())
        return 0
    print(__doc__)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
