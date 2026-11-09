"""
gateway.py
~~~~~~~~~~
Where agents connect. Each agent keeps one WebSocket open (it dials out,
so hosts need no open port); this side sends it tasks and records what
comes back.

Messages, all JSON with a "type":
  agent → server   hello {facts, version} · inventory {result} · log {task_id, text}
                   result {task_id, result} · pong
  server → agent   welcome {host_id, scan_interval_min} · task {task_id, op, args}
                   reboot {task_id} · ping
"""

from __future__ import annotations

import asyncio
import json
import logging
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import psycopg
from fastapi import APIRouter, HTTPException, Request, WebSocket, WebSocketDisconnect
from fastapi.responses import PlainTextResponse, Response

from . import config, db, fleet, security, tls
from .worker import apply_detail, record_apply, wants_reboot

log = logging.getLogger("fleetwright.gateway")
router = APIRouter()

AGENT_DIR = Path(__file__).resolve().parent.parent / "agent"
AGENT_FILES = {"fleetwright_agent.py": AGENT_DIR / "fleetwright_agent.py",
               "pkgops.py": Path(__file__).parent / "pkgops.py",
               "fleetwright-agent.service": AGENT_DIR / "fleetwright-agent.service"}
NAME_OK = re.compile(r"[^A-Za-z0-9._-]+")


class AgentConn:
    def __init__(self, host_id: int, ws: WebSocket):
        self.host_id = host_id
        self.ws = ws
        self.lock = asyncio.Lock()

    async def send(self, msg: dict) -> None:
        async with self.lock:
            await self.ws.send_text(json.dumps(msg))


connected: dict[int, AgentConn] = {}
_wake = asyncio.Event()


# ─── Enrolment and the install script ───────────────────────────────────────

@router.post("/api/agent/enroll")
async def enroll(request: Request):
    body = await request.json()
    token = str(body.get("token", ""))
    facts = body.get("facts") or {}
    row = await db.fetchone(
        """UPDATE enroll_tokens SET uses_left = CASE WHEN uses_left IS NULL THEN NULL ELSE uses_left - 1 END
            WHERE token_hash = %s AND expires_at > NOW() AND (uses_left IS NULL OR uses_left > 0)
        RETURNING id, group_id, tags, label""", security.token_hash(token))
    if not row:
        raise HTTPException(403, "That enrolment token is wrong, used up or expired")
    hostname = str(facts.get("hostname") or "").strip()
    if hostname.split(".")[0] in ("", "localhost"):
        # An unnamed host (a fresh cloud image): name it after its address instead.
        hostname = str(facts.get("address") or (request.client.host if request.client else "host"))
    name = NAME_OK.sub("-", hostname)[:120].strip("-") or "host"
    agent_token = security.new_token()
    existing = None
    if facts.get("machine_id"):
        # The same machine enrolling again (a reinstall) keeps its host, name and history.
        existing = await db.fetchone("SELECT id, mode, name FROM hosts WHERE machine_id = %s AND mode = 'agent'",
                                     str(facts["machine_id"]))
        if existing:
            name = existing["name"]
    existing = existing or await db.fetchone("SELECT id, mode FROM hosts WHERE name = %s", name)
    if existing and existing["mode"] == "agent":
        host_id = existing["id"]
        await db.execute("UPDATE hosts SET agent_token_hash = %s WHERE id = %s",
                         security.token_hash(agent_token), host_id)
        what = f"Re-enrolled agent on {name}"
    else:
        if existing:
            name = f"{name}-{security.new_token(3).lower()}"
        host_id = await db.fetchval(
            """INSERT INTO hosts (name, address, mode, group_id, tags, agent_token_hash)
               VALUES (%s, %s, 'agent', %s, %s, %s) RETURNING id""",
            name, str(facts.get("address") or (request.client.host if request.client else "")),
            row["group_id"], row["tags"],
            security.token_hash(agent_token))
        what = f"Enrolled agent on {name}"
    if facts.get("os_id"):
        await fleet.record_facts(host_id, facts)
    await db.audit(f"enrolment token {row['label'] or row['id']}", what)
    return {"host_id": host_id, "name": name, "agent_token": agent_token}


@router.get("/agent/files/{name}")
async def agent_file(name: str):
    path = AGENT_FILES.get(name)
    if not path or not path.exists():
        raise HTTPException(404)
    return Response(path.read_bytes(), media_type="text/plain; charset=utf-8")


def server_pin() -> str:
    """The certificate's public-key pin when FleetWright serves HTTPS itself, else ''."""
    info = tls.current() if config.TLS_ON else None
    return info.spki_pin if info else ""


def install_command(token: str) -> str:
    """The one line an admin runs on a host to install and enrol the agent."""
    url = f"{config.PUBLIC_URL}/agent/install.sh"
    if config.PUBLIC_URL.startswith("http://"):
        return f"curl -fsSL {url} | sudo sh -s -- {token} --insecure"
    pin = server_pin()
    if pin:
        # -k skips the CA check; --pinnedpubkey still refuses any key but this server's.
        return f"curl -fsSL -k --pinnedpubkey 'sha256//{pin}' {url} | sudo sh -s -- {token}"
    return f"curl -fsSL {url} | sudo sh -s -- {token}"


@router.get("/agent/install.sh")
async def install_script():
    text = (AGENT_DIR / "install.sh").read_text().replace("@@SERVER@@", config.PUBLIC_URL) \
        .replace("@@PIN@@", server_pin())
    return PlainTextResponse(text, media_type="text/x-shellscript")


@router.get("/agent/server.pem")
async def server_pem():
    pem = tls.leaf_pem() if config.TLS_ON else ""
    if not pem:
        raise HTTPException(404, "FleetWright isn't serving HTTPS itself")
    return PlainTextResponse(pem, media_type="application/x-pem-file")


async def push_trust(pem: str) -> int:
    """Send a certificate to every connected agent to add to its trust store."""
    sent = 0
    for conn in list(connected.values()):
        try:
            await conn.send({"type": "trust", "pem": pem})
            sent += 1
        except Exception:  # noqa: BLE001
            pass
    return sent


# ─── The WebSocket ──────────────────────────────────────────────────────────

@router.websocket("/api/agent/ws")
async def agent_ws(ws: WebSocket):
    auth = ws.headers.get("authorization", "")
    token = auth[7:] if auth.lower().startswith("bearer ") else ""
    host = await db.fetchone("SELECT * FROM hosts WHERE agent_token_hash = %s AND mode = 'agent'",
                             security.token_hash(token)) if token else None
    if not host:
        await ws.close(code=4401)
        return
    await ws.accept()
    hid = host["id"]
    old = connected.get(hid)
    conn = AgentConn(hid, ws)
    connected[hid] = conn
    if old:
        try:
            await old.ws.close(code=4409)
        except Exception:  # noqa: BLE001
            pass
    await db.execute("UPDATE hosts SET agent_connected = TRUE, last_seen = NOW() WHERE id = %s", hid)
    await conn.send({"type": "welcome", "host_id": hid, "scan_interval_min": config.SCAN_INTERVAL_MIN})
    if config.TLS_ON:
        await conn.send({"type": "trust", "pem": tls.leaf_pem()})
    try:
        while True:
            msg = json.loads(await ws.receive_text())
            await handle(conn, msg)
    except (WebSocketDisconnect, RuntimeError):
        pass
    except Exception:  # noqa: BLE001
        log.exception("agent %s connection failed", hid)
    finally:
        if connected.get(hid) is conn:
            del connected[hid]
            await db.execute("UPDATE hosts SET agent_connected = FALSE WHERE id = %s", hid)
            n = await db.execute(
                """UPDATE tasks SET status = 'failed', finished_at = NOW(),
                          detail = 'The agent disconnected before finishing'
                    WHERE host_id = %s AND status = 'running' AND COALESCE(detail, '') <> 'rebooting'""", hid)
            if n:
                await db.notify(fleet.TASK_CHANNEL, "done")


async def handle(conn: AgentConn, msg: dict) -> None:
    hid = conn.host_id
    kind = msg.get("type")
    if kind == "hello":
        facts = msg.get("facts") or {}
        await fleet.record_facts(hid, facts)
        await db.execute("UPDATE hosts SET agent_version = %s, last_error = NULL WHERE id = %s",
                         str(msg.get("version", ""))[:40], hid)
        await finish_reboots(hid, facts.get("boot_id"))
        stale = await db.fetchval(
            """SELECT last_scan_at IS NULL OR last_scan_at < NOW() - make_interval(mins => %s)
                 FROM hosts WHERE id = %s""", config.SCAN_INTERVAL_MIN, hid)
        if stale:
            await fleet.queue_scan([hid])
        _wake.set()
    elif kind == "inventory":
        result = msg.get("result") or {}
        if result.get("ok"):
            await fleet.record_scan(hid, result)
        else:
            await db.execute("UPDATE hosts SET last_error = %s, last_seen = NOW() WHERE id = %s",
                             str(result.get("error", ""))[:500], hid)
    elif kind == "log":
        task = await _own_task(hid, msg.get("task_id"))
        if task:
            await fleet.append_log(task["id"], str(msg.get("text", ""))[:200_000])
    elif kind == "result":
        task = await _own_task(hid, msg.get("task_id"))
        if task:
            await task_result(conn, task, msg.get("result") or {})
    elif kind == "pong":
        await db.execute("UPDATE hosts SET last_seen = NOW() WHERE id = %s", hid)


async def _own_task(host_id: int, task_id) -> Optional[dict]:
    try:
        tid = int(task_id)
    except (TypeError, ValueError):
        return None
    return await db.fetchone("SELECT * FROM tasks WHERE id = %s AND host_id = %s AND status = 'running'",
                             tid, host_id)


def _stamp(text: str) -> str:
    return f"{datetime.now(timezone.utc):%H:%M:%S} {text}\n"


async def task_result(conn: AgentConn, task: dict, result: dict) -> None:
    ok = bool(result.get("ok"))
    if not ok:
        await fleet.append_log(task["id"], _stamp(f"✗ {result.get('error', 'failed')}"))
        await db.execute("UPDATE hosts SET last_error = %s WHERE id = %s",
                         str(result.get("error", ""))[:500], task["host_id"])
        await fleet.finish_task(task["id"], False, str(result.get("error", "failed"))[:500], result)
        return
    if task["op"] == "scan":
        await fleet.record_scan(task["host_id"], result)
        await fleet.append_log(task["id"], _stamp("✓ done"))
        await fleet.finish_task(task["id"], True, f"{result.get('pending_count', 0)} pending", result)
    elif task["op"] == "apply":
        await record_apply(task, result)
        detail = apply_detail(result)
        if wants_reboot((task["args"] or {}).get("reboot", "never"), result):
            await start_reboot(conn, task, detail)
        else:
            await fleet.append_log(task["id"], _stamp("✓ done"))
            await fleet.finish_task(task["id"], True, detail, result)


async def start_reboot(conn: AgentConn, task: dict, before_detail: str = "") -> None:
    host = await db.fetchone("SELECT boot_id FROM hosts WHERE id = %s", task["host_id"])
    await db.execute("UPDATE tasks SET detail = 'rebooting', result = %s WHERE id = %s",
                     db.J({"boot_id_before": host["boot_id"], "before": before_detail,
                           "reboot_started": datetime.now(timezone.utc).isoformat()}), task["id"])
    await fleet.append_log(task["id"], _stamp("▸ reboot; waiting for the agent to reconnect…"))
    await conn.send({"type": "reboot", "task_id": task["id"]})


async def finish_reboots(host_id: int, boot_id: Optional[str]) -> None:
    for t in await db.fetch("""SELECT * FROM tasks WHERE host_id = %s AND status = 'running'
                                 AND detail = 'rebooting'""", host_id):
        before = (t["result"] or {}).get("boot_id_before")
        if boot_id and boot_id != before:
            prefix = (t["result"] or {}).get("before") or ""
            await fleet.append_log(t["id"], _stamp("host is back · ✓ done"))
            await fleet.finish_task(t["id"], True, f"{prefix}, rebooted" if prefix else "Rebooted")
            await fleet.queue_scan([host_id])


# ─── Handing tasks to agents ────────────────────────────────────────────────

CLAIM_SQL = """
UPDATE tasks SET status = 'running', claimed_by = 'gateway', started_at = NOW()
 WHERE id IN (
    SELECT t.id FROM tasks t
     WHERE t.status = 'queued' AND t.host_id = ANY(%s)
       AND t.id = (SELECT MIN(q.id) FROM tasks q WHERE q.host_id = t.host_id AND q.status = 'queued')
       AND NOT EXISTS (SELECT 1 FROM tasks r WHERE r.host_id = t.host_id AND r.status = 'running')
     ORDER BY t.id LIMIT 500
       FOR UPDATE OF t SKIP LOCKED)
RETURNING *"""


async def dispatch_once() -> None:
    if not connected:
        return
    for task in await db.fetch(CLAIM_SQL, list(connected)):
        conn = connected.get(task["host_id"])
        try:
            if conn is None:
                raise ConnectionError("agent went away")
            if task["op"] == "reboot":
                await start_reboot(conn, task)
            else:
                await conn.send({"type": "task", "task_id": task["id"], "op": task["op"],
                                 "args": task["args"] or {}})
        except Exception as e:  # noqa: BLE001
            log.warning("couldn't hand task %s to agent %s: %s", task["id"], task["host_id"], e)
            await db.execute("UPDATE tasks SET status = 'queued', claimed_by = NULL, started_at = NULL "
                             "WHERE id = %s", task["id"])


async def dispatcher() -> None:
    while True:
        try:
            await dispatch_once()
        except Exception:  # noqa: BLE001
            log.exception("dispatch failed")
        _wake.clear()
        try:
            await asyncio.wait_for(_wake.wait(), timeout=3)
        except asyncio.TimeoutError:
            pass


async def listener() -> None:
    while True:
        try:
            async with await psycopg.AsyncConnection.connect(config.DATABASE_URL, autocommit=True) as c:
                await c.execute(f"LISTEN {fleet.TASK_CHANNEL}")
                async for _ in c.notifies():
                    _wake.set()
        except (psycopg.Error, OSError) as e:
            log.warning("gateway LISTEN lost (%s); retrying", e)
            await asyncio.sleep(5)


async def pinger() -> None:
    while True:
        await asyncio.sleep(60)
        for conn in list(connected.values()):
            try:
                await conn.send({"type": "ping"})
            except Exception:  # noqa: BLE001
                pass


async def startup() -> list[asyncio.Task]:
    # Nothing is connected to a gateway that just started.
    await db.execute("UPDATE hosts SET agent_connected = FALSE WHERE agent_connected")
    return [asyncio.create_task(dispatcher()), asyncio.create_task(listener()),
            asyncio.create_task(pinger())]
