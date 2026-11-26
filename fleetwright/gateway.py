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
import hashlib
import json
import logging
import re
import secrets
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

import psycopg
from psycopg import sql
from fastapi import APIRouter, HTTPException, Request, WebSocket, WebSocketDisconnect
from fastapi.responses import PlainTextResponse, Response
from pydantic import BaseModel, ConfigDict, ValidationError

from . import config, db, fleet, security, tls
from .worker import apply_detail, record_apply, scan_detail, wants_reboot

log = logging.getLogger("fleetwright.gateway")
router = APIRouter()

AGENT_DIR = Path(__file__).resolve().parent.parent / "agent"
AGENT_FILES = {"fleetwright_agent.py": AGENT_DIR / "fleetwright_agent.py",
               "pkgops.py": Path(__file__).parent / "pkgops.py",
               "fleetwright-agent.service": AGENT_DIR / "fleetwright-agent.service"}
NAME_OK = re.compile(r"[^A-Za-z0-9._-]+")
BUNDLE_FILES = ("fleetwright_agent.py", "pkgops.py")
RESTARTING = "restarting agent"   # a running agent_update task waiting for the new agent to say hello


def agent_bundle() -> dict:
    """The agent this server hands out: its version, each file's SHA-256 and one id for
    the set (computed as the agent's bundle_id does)."""
    global _bundle
    if _bundle is None:
        hashes = {n: hashlib.sha256(AGENT_FILES[n].read_bytes()).hexdigest() for n in BUNDLE_FILES}
        joined = "".join(f"{n}:{hashes[n]}\n" for n in sorted(hashes))
        m = re.search(r'^AGENT_VERSION = "([^"]+)"', AGENT_FILES["fleetwright_agent.py"].read_text(), re.M)
        _bundle = {"version": m.group(1) if m else "?", "files": hashes,
                   "bundle": hashlib.sha256(joined.encode()).hexdigest()[:16]}
    return _bundle


_bundle: Optional[dict] = None


class AgentConn:
    def __init__(self, host_id: int, ws: WebSocket):
        self.host_id = host_id
        self.ws = ws
        self.lock = asyncio.Lock()
        # tasks.claimed_by for the tasks handed to this connection
        self.tag = f"gateway:{secrets.token_hex(4)}"

    async def send(self, msg: dict) -> None:
        async with self.lock:
            await self.ws.send_text(json.dumps(msg))


connected: dict[int, AgentConn] = {}
# Each host's recent hellos (which machine, time), to spot two machines sharing one identity.
recent_boots: dict[int, list[tuple[str, float]]] = {}
SHARED_TOKEN = ("Two machines are using this host's agent identity and keep replacing each other's "
                "connection: one is probably a clone made after the agent was installed. On the clone, "
                "give it its own /etc/machine-id, delete /etc/fleetwright-agent and run the install command.")


def shared_identity(seen: list[tuple[str, float]], window: float = 600) -> bool:
    """Hellos alternating between two machines (A, B, A) within the window. A machine is
    its boot id, hostname and address together: containers on one kernel share a boot
    id. A reboot or a new address goes A → B and doesn't come back; a reconnect stays on A."""
    if len(seen) < 3:
        return False
    (a, ta), (b, _), (c, tc) = seen[-3:]
    return a == c != b and tc - ta <= window
_wake = asyncio.Event()


# ─── Enrolment and the install script ───────────────────────────────────────

def same_machine(facts: dict, hostname: str, candidates: list[dict]) -> Optional[dict]:
    """Which of the agent hosts sharing this /etc/machine-id (if any) the enrolling
    machine is. A reinstall has the same hostname and, while its old agent is still
    connected (install.sh enrols before restarting it), the same boot. Anything else
    sharing the id is a cloned machine (a VM template, an image whose machine-id
    wasn't regenerated) and gets a host of its own rather than taking this one over.
    Not the boot id alone: containers on one kernel all report the kernel's."""
    boot = facts.get("boot_id")
    for c in candidates:
        if (c.get("hostname") or c.get("name")) != hostname:
            continue
        if not c.get("agent_connected") or (boot and c.get("boot_id") == boot):
            return c
    return None


class EnrollFacts(BaseModel):
    """Facts an agent reports about itself. Newer agents may add fields, but the ones
    the server uses must have the right shape: a string where a string is expected."""
    model_config = ConfigDict(extra="allow")
    hostname: Optional[str] = None
    address: Optional[str] = None
    machine_id: Optional[str] = None
    boot_id: Optional[str] = None
    os_id: Optional[str] = None
    os_version: Optional[str] = None
    os_pretty: Optional[str] = None
    family: Optional[str] = None
    kernel: Optional[str] = None
    booted_at: Optional[int] = None
    pkgops: Optional[str] = None


class EnrollIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    token: str = ""
    facts: EnrollFacts


def checked_enroll(body: Any) -> EnrollIn:
    """Validate the whole request before the token is spent. Otherwise a malformed
    facts value raises an AttributeError after the UPDATE has already committed, and
    a legitimate agent retrying with the single-use token gets a 403."""
    try:
        return EnrollIn.model_validate(body)
    except ValidationError as e:
        raise HTTPException(400, "Bad request") from e


@router.post("/api/agent/enroll")
async def enroll(request: Request):
    body = checked_enroll(await request.json())
    token = body.token
    facts = body.facts.model_dump(exclude_none=True)
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
    reuse, clone_of = None, None
    machine_id = str(facts.get("machine_id") or "")
    if machine_id:
        # The same machine enrolling again (a reinstall) keeps its host, name and history.
        candidates = await db.fetch("""SELECT id, name, hostname, boot_id, agent_connected FROM hosts
                                        WHERE machine_id = %s AND mode = 'agent' ORDER BY id""", machine_id)
        reuse = same_machine(facts, str(facts.get("hostname") or ""), candidates)
        if not reuse and candidates:
            clone_of = candidates[0]["name"]
    if reuse:
        name = reuse["name"]
    else:
        taken = await db.fetchone("SELECT id, mode, machine_id FROM hosts WHERE name = %s", name)
        # By name only for an agent host enrolled before machine ids were recorded; a
        # different machine that happens to share a hostname mustn't take a host over.
        if taken and taken["mode"] == "agent" and not taken["machine_id"] and not clone_of:
            reuse = taken
        elif taken:
            name = f"{name}-{security.new_token(3).lower()}"
    if reuse:
        host_id = reuse["id"]
        await db.execute("UPDATE hosts SET agent_token_hash = %s WHERE id = %s",
                         security.token_hash(agent_token), host_id)
        what = f"Re-enrolled agent on {name}"
    else:
        host_id = await db.fetchval(
            """INSERT INTO hosts (name, address, mode, group_id, tags, agent_token_hash)
               VALUES (%s, %s, 'agent', %s, %s, %s) RETURNING id""",
            name, str(facts.get("address") or (request.client.host if request.client else "")),
            row["group_id"], row["tags"],
            security.token_hash(agent_token))
        what = f"Enrolled agent on {name}"
        if clone_of:
            what += (f" (it has the same /etc/machine-id as {clone_of}: a cloned machine? "
                     "Give it its own, then reinstall the agent)")
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
            which, arg = "host_id = %s", hid
        else:
            # Replaced by a newer connection (the agent reconnected or re-enrolled): only
            # what was handed to this one is lost.
            which, arg = "claimed_by = %s", conn.tag
        n = await db.execute(
            f"""UPDATE tasks SET status = 'failed', finished_at = NOW(),
                       detail = 'The agent disconnected before finishing'
                 WHERE {which} AND status = 'running'
                   AND COALESCE(detail, '') NOT IN ('rebooting', %s)""", arg, RESTARTING)
        if n:
            await db.notify(fleet.TASK_CHANNEL, "done")


async def handle(conn: AgentConn, msg: dict) -> None:
    hid = conn.host_id
    kind = msg.get("type")
    if kind == "hello":
        facts = msg.get("facts") or {}
        await fleet.record_facts(hid, facts)
        bundle = str(msg.get("bundle") or "")[:40] or None
        await db.execute("UPDATE hosts SET agent_version = %s, agent_bundle = %s, last_error = NULL WHERE id = %s",
                         str(msg.get("version", ""))[:40], bundle, hid)
        if facts.get("boot_id"):
            seen = recent_boots.setdefault(hid, [])
            machine = f"{facts['boot_id']}|{facts.get('hostname', '')}|{facts.get('address', '')}"
            seen.append((machine, time.monotonic()))
            del seen[:-3]
            if shared_identity(seen):
                log.warning("host %s: two machines share one agent identity", hid)
                await db.execute("UPDATE hosts SET last_error = %s WHERE id = %s", SHARED_TOKEN, hid)
        await finish_reboots(hid, facts.get("boot_id"))
        await finish_agent_updates(hid, str(msg.get("version", "")), bundle)
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
    if task["op"] in ("scan", "auto_off"):
        await fleet.record_scan(task["host_id"], result)
        await fleet.append_log(task["id"], _stamp("✓ done"))
        await fleet.finish_task(task["id"], True, scan_detail(task["op"], result), result)
    elif task["op"] == "agent_update":
        if result.get("restarting"):
            # Done once the new agent connects and says which version it is.
            await db.execute("UPDATE tasks SET detail = %s, result = %s WHERE id = %s", RESTARTING,
                             db.J({"bundle": result.get("bundle"), "version": result.get("version"),
                                   "reboot_started": datetime.now(timezone.utc).isoformat()}), task["id"])
            await fleet.append_log(task["id"], _stamp("▸ waiting for the new agent to connect…"))
        else:
            await fleet.append_log(task["id"], _stamp("✓ done"))
            await fleet.finish_task(task["id"], True, "Already up to date", result)
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


def outdated_sql() -> str:
    """Agent hosts whose agent isn't this server's. A constant fragment: the bundle id comes
    from hashing this server's own agent files, and is checked to be hex before it's inlined."""
    bundle = agent_bundle()["bundle"]
    if not re.fullmatch(r"[0-9a-f]{16}", bundle):
        raise ValueError(f"unexpected agent bundle id {bundle!r}")
    return f"(h.mode = 'agent' AND h.agent_bundle IS DISTINCT FROM '{bundle}')"


async def start_agent_update(actor: str, host_ids: list[int], title: str = "Update agents") -> Optional[int]:
    """A run updating those of host_ids whose agent can update itself (0.3.0 on) and
    differs from this server's: a canary first, then a tenth at a time, stopping at
    the first failure. None when there's nothing to update."""
    rows = await db.fetch(f"""SELECT id FROM hosts h WHERE id = ANY(%s) AND {outdated_sql()}
                                AND agent_bundle IS NOT NULL""", host_ids)
    ids = [r["id"] for r in rows]
    if not ids:
        return None
    return await fleet.create_run(kind="agent_update", title=title, actor=actor, host_ids=ids,
                                  canary=len(ids) > 1, batch_percent=10, max_failures=1)


async def finish_agent_updates(host_id: int, version: str, bundle: Optional[str]) -> None:
    for t in await db.fetch("SELECT * FROM tasks WHERE host_id = %s AND status = 'running' AND detail = %s",
                            host_id, RESTARTING):
        want = (t["result"] or {}).get("bundle")
        ok = bool(bundle) and bundle == want
        text = f"Updated to {version}" if ok else f"The agent came back as {version or '?'}, not the new version"
        await fleet.append_log(t["id"], _stamp(("✓ " if ok else "✗ ") + text))
        await fleet.finish_task(t["id"], ok, text)


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
                # An agent update always offers what this server has now.
                args = agent_bundle() if task["op"] == "agent_update" else task["args"] or {}
                await conn.send({"type": "task", "task_id": task["id"], "op": task["op"], "args": args})
                await db.execute("UPDATE tasks SET claimed_by = %s WHERE id = %s", conn.tag, task["id"])
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
                await c.execute(sql.SQL("LISTEN {}").format(sql.Identifier(fleet.TASK_CHANNEL)))
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
    # Nothing is connected to a gateway that just started, so nothing it handed out is
    # still being worked on, except reboots and agent updates, which finish when the
    # agent says hello again.
    await db.execute("UPDATE hosts SET agent_connected = FALSE WHERE agent_connected")
    n = await db.execute("""UPDATE tasks SET status = 'failed', finished_at = NOW(),
                                   detail = 'FleetWright restarted while the agent was on this'
                             WHERE status = 'running' AND claimed_by LIKE 'gateway%%'
                               AND COALESCE(detail, '') NOT IN ('rebooting', %s)""", RESTARTING)
    if n:
        log.warning("failed %d agent tasks interrupted by a restart", n)
    return [asyncio.create_task(dispatcher()), asyncio.create_task(listener()),
            asyncio.create_task(pinger())]
