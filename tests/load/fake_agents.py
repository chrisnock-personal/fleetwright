"""
fake_agents.py
~~~~~~~~~~~~~~
Hundreds of simulated FleetWright agents in one process, each with its own
enrolment, WebSocket and made-up packages (fakepkgs). They speak the real
protocol: hello, inventory, log, result, pong; and they act on scan, apply,
auto_off and reboot (disconnect, wait, come back with a new boot id).

Runs inside the FleetWright image (it has websockets), on the compose network:
    python /load/fake_agents.py --server https://web:8443 --token TOKEN --count 500

Every 10 s it prints how many are connected and what they've done.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import random
import ssl
import sys
import time
import urllib.request
import uuid

import websockets

sys.path.insert(0, "/app")
sys.path.insert(0, "/load")
import fakepkgs  # noqa: E402
from fleetwright import pkgops  # noqa: E402

CTX = ssl.create_default_context()
CTX.check_hostname = False
CTX.verify_mode = ssl.CERT_NONE
STATS = {"connected": 0, "connects": 0, "scans": 0, "applies": 0, "reboots": 0, "inventories": 0,
         "errors": 0, "task_ms": []}


def enroll(server: str, token: str, facts: dict) -> str:
    req = urllib.request.Request(f"{server}/api/agent/enroll",
                                 data=json.dumps({"token": token, "facts": facts}).encode(),
                                 headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=60, context=CTX) as r:
        return json.load(r)["agent_token"]


class FakeAgent:
    def __init__(self, n: int, args):
        self.n, self.args = n, args
        self.seed = 100_000 + n
        self.applied: set[str] = set()
        self.boot_id = str(uuid.uuid4())
        self.booted = int(time.time()) - random.randint(3600, 90 * 86400)
        self.machine_id = uuid.UUID(int=self.seed).hex
        self.token = None
        self.ws = None
        self.reboot_pending = False

    def facts(self) -> dict:
        return {"hostname": f"load-agent-{self.n:04d}", "machine_id": self.machine_id, "os_id": "ubuntu",
                "os_version": "24.04", "os_pretty": "Ubuntu 24.04.1 LTS (simulated)", "family": "apt",
                "kernel": "6.8.0-49-generic", "boot_id": self.boot_id, "booted_at": self.booted,
                "pkgops": pkgops.VERSION, "address": f"10.99.{self.n // 250}.{self.n % 250 + 1}"}

    def scan(self) -> dict:
        _, pending = fakepkgs.host(self.seed, self.applied)
        return {"ok": True, "facts": self.facts(), "pending": pending, "reboot_required": self.reboot_pending,
                "os_holds": [], "auto_updates": [],
                "pending_count": len(pending), "security_count": sum(p["is_security"] for p in pending)}

    async def send(self, msg: dict) -> None:
        await self.ws.send(json.dumps(msg))

    async def task(self, msg: dict) -> None:
        tid, op, args = msg.get("task_id"), msg.get("op"), msg.get("args") or {}
        t0 = time.monotonic()
        for line in ("▸ scan (apt)", "$ apt-get update -q", "  Hit:1 http://archive.ubuntu.com noble InRelease"):
            await self.send({"type": "log", "task_id": tid, "text": f"{time.strftime('%H:%M:%S')} {line}\n"})
        if op in ("scan", "auto_off"):
            await asyncio.sleep(random.uniform(*self.args.scan_secs))
            result = self.scan()
            STATS["scans"] += 1
        elif op == "apply":
            await asyncio.sleep(random.uniform(*self.args.apply_secs))
            before = self.scan()
            chosen, skipped = pkgops.select(before["pending"], args.get("selection") or {"mode": "all"},
                                            (args.get("selection") or {}).get("held") or [])
            self.applied |= {p["name"] for p in chosen}
            if any(p["is_kernel"] for p in chosen):
                self.reboot_pending = True
            result = dict(self.scan(), planned=len(chosen),
                          changes=[{"name": f"{p['name']}:amd64", "from": p["current"], "to": p["available"]}
                                   for p in chosen],
                          skipped=[{"name": s["name"], "why": s["why"]} for s in skipped])
            STATS["applies"] += 1
        else:
            result = {"ok": False, "error": f"operation {op} isn't allowed"}
        STATS["task_ms"].append((time.monotonic() - t0) * 1000)
        await self.send({"type": "result", "task_id": tid, "result": result})

    async def inventory_loop(self) -> None:
        while True:
            await asyncio.sleep(self.args.inventory_every * random.uniform(0.9, 1.1))
            await self.send({"type": "inventory", "result": self.scan()})
            STATS["inventories"] += 1

    async def session(self) -> None:
        url = self.args.server.replace("https://", "wss://") + "/api/agent/ws"
        self.ws = await websockets.connect(url, additional_headers={"Authorization": f"Bearer {self.token}"},
                                           ssl=CTX, max_size=2**24, ping_interval=30, ping_timeout=120,
                                           open_timeout=60)
        STATS["connected"] += 1
        STATS["connects"] += 1
        inv = asyncio.create_task(self.inventory_loop()) if self.args.inventory_every else None
        jobs: set = set()
        try:
            await self.send({"type": "hello", "version": "0.2.0", "facts": self.facts()})
            async for raw in self.ws:
                msg = json.loads(raw)
                kind = msg.get("type")
                if kind == "task":
                    t = asyncio.create_task(self.task(msg))
                    jobs.add(t)
                    t.add_done_callback(jobs.discard)
                elif kind == "ping":
                    await self.send({"type": "pong"})
                elif kind == "reboot":
                    STATS["reboots"] += 1
                    await self.ws.close()
                    await asyncio.sleep(random.uniform(10, 30))
                    self.boot_id, self.booted, self.reboot_pending = str(uuid.uuid4()), int(time.time()), False
                    return
        finally:
            STATS["connected"] -= 1
            if inv:
                inv.cancel()

    async def run(self, enrol_gate: asyncio.Semaphore) -> None:
        async with enrol_gate:
            self.token = await asyncio.to_thread(enroll, self.args.server, self.args.token, self.facts())
        while True:
            try:
                await self.session()
            except Exception as e:  # noqa: BLE001
                STATS["errors"] += 1
                if self.args.verbose:
                    print(f"agent {self.n}: {e}", flush=True)
                await asyncio.sleep(random.uniform(2, 10))


async def report() -> None:
    while True:
        await asyncio.sleep(10)
        ms = sorted(STATS["task_ms"])
        p50 = ms[len(ms) // 2] if ms else 0
        print(f"{time.strftime('%H:%M:%S')} connected {STATS['connected']} · connects {STATS['connects']} · "
              f"scans {STATS['scans']} · applies {STATS['applies']} · reboots {STATS['reboots']} · "
              f"inventories {STATS['inventories']} · errors {STATS['errors']} · task p50 {p50:.0f} ms", flush=True)


async def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--server", required=True)
    ap.add_argument("--token", required=True)
    ap.add_argument("--count", type=int, default=300)
    ap.add_argument("--first", type=int, default=0, help="number of the first agent (to add more later)")
    ap.add_argument("--inventory-every", type=float, default=0, help="seconds between unprompted inventories")
    ap.add_argument("--scan-secs", type=float, nargs=2, default=(1, 4))
    ap.add_argument("--apply-secs", type=float, nargs=2, default=(3, 8))
    ap.add_argument("--verbose", action="store_true")
    args = ap.parse_args()
    gate = asyncio.Semaphore(20)
    agents = [FakeAgent(args.first + i, args) for i in range(args.count)]
    asyncio.create_task(report())
    await asyncio.gather(*(a.run(gate) for a in agents))


if __name__ == "__main__":
    asyncio.run(main())
