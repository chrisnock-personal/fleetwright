"""
fleet.py
~~~~~~~~
The core: turning targets into hosts, runs into tasks, scan results into
rows, and moving runs through their batches. Used by the web app, the
agent gateway and the worker.
"""

from __future__ import annotations

import logging
import math
from datetime import datetime, timedelta, timezone
from typing import Iterable, Optional

from . import db
from .db import J
from .schedule import next_run

log = logging.getLogger("fleetwright.fleet")

KINDS = ["security", "kernel", "bugfix", "enhancement"]
KIND_LABELS = {"security": "Security", "kernel": "Kernel", "bugfix": "Bug fixes",
               "enhancement": "Enhancements"}
SEVERITIES = ["critical", "important", "moderate", "low"]
REBOOT_CHOICES = {"never": "Never", "if_needed": "If needed", "always": "Always"}
WINDOW_CLOSE = {"finish_started": "Finish hosts already started, start no new ones",
                "stop": "Stop at once (running hosts finish their current step)",
                "carry_on": "Carry on until done"}
TASK_CHANNEL = "fw_tasks"


def now() -> datetime:
    return datetime.now(timezone.utc)


# ─── Targets ────────────────────────────────────────────────────────────────

async def resolve_target(target: dict) -> list[int]:
    """{"hosts": [...], "groups": [...], "tags": [...], "exclude_tags": [...], "all": bool}"""
    hosts = [int(h) for h in target.get("hosts") or []]
    groups = [int(g) for g in target.get("groups") or []]
    tags = list(target.get("tags") or [])
    rows = await db.fetch(
        """SELECT id FROM hosts
            WHERE (%s OR id = ANY(%s) OR group_id = ANY(%s) OR tags && %s::text[])
              AND NOT (tags && %s::text[])
            ORDER BY name""",
        bool(target.get("all")), hosts, groups, tags, list(target.get("exclude_tags") or []))
    return [r["id"] for r in rows]


async def describe_target(target: dict) -> str:
    parts = []
    if target.get("all"):
        parts.append("All hosts")
    if target.get("groups"):
        rows = await db.fetch("SELECT name FROM groups WHERE id = ANY(%s) ORDER BY name",
                              [int(g) for g in target["groups"]])
        parts.append(", ".join(r["name"] for r in rows))
    if target.get("tags"):
        parts.append("tag " + ", ".join(target["tags"]))
    if target.get("hosts"):
        rows = await db.fetch("SELECT name FROM hosts WHERE id = ANY(%s) ORDER BY name",
                              [int(h) for h in target["hosts"]])
        names = [r["name"] for r in rows]
        parts.append(", ".join(names[:4]) + (f" +{len(names) - 4}" if len(names) > 4 else ""))
    text = " · ".join(p for p in parts if p) or "No hosts"
    if target.get("exclude_tags"):
        text += " · not tag " + ", ".join(target["exclude_tags"])
    return text


def describe_selection(sel: dict) -> str:
    mode = sel.get("mode", "all")
    if mode == "all":
        text = "Everything"
    elif mode == "packages":
        pkgs = sel.get("packages") or {}
        # A run holds them per host ({host id: [...]}); each of its tasks holds one host's list.
        n = sum(len(v) for v in pkgs.values()) if isinstance(pkgs, dict) else len(pkgs)
        text = f"{n} picked update{'s' if n != 1 else ''}"
    else:
        kinds = [KIND_LABELS.get(k, k) for k in sel.get("kinds") or []]
        text = ", ".join(kinds) or "Nothing"
        if "security" in (sel.get("kinds") or []) and sel.get("min_severity"):
            text += f" ({sel['min_severity']}+)"
        if sel.get("include"):
            text += " + " + ", ".join(sel["include"])
    if sel.get("exclude"):
        text += " · never " + ", ".join(sel["exclude"])
    return text


# ─── Runs ───────────────────────────────────────────────────────────────────

def batches_for(n: int, batch_size: int, canary: bool) -> list[int]:
    """The batch number for each of n hosts, in order."""
    out, i, b = [], 0, 0
    if canary and n > 1:
        out.append(0)
        i, b = 1, 1
    size = batch_size if batch_size > 0 else n
    while i < n:
        take = min(size, n - i)
        out.extend([b] * take)
        i += take
        b += 1
    return out


async def create_run(*, kind: str, title: str, actor: str, host_ids: list[int],
                     selection: Optional[dict] = None, batch_size: int = 0, batch_percent: int = 0,
                     canary: bool = False, max_failures: int = 0, reboot: str = "never",
                     window_end: Optional[datetime] = None, on_window_close: str = "finish_started",
                     policy_id: Optional[int] = None, booking_id: Optional[int] = None) -> int:
    selection = selection or {"mode": "all"}
    if batch_size <= 0 and batch_percent > 0:
        batch_size = max(1, math.ceil(len(host_ids) * batch_percent / 100))
    hosts = await db.fetch("SELECT id, held FROM hosts WHERE id = ANY(%s) ORDER BY name", host_ids)
    async with db.transaction() as conn:
        cur = await conn.execute(
            """INSERT INTO runs (kind, title, created_by, policy_id, booking_id, selection, batch_size,
                                 canary, max_failures, reboot, window_end, on_window_close, status)
               VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s) RETURNING id""",
            (kind, title, actor, policy_id, booking_id, J(selection), batch_size, canary,
             max_failures, reboot, window_end, on_window_close, "running" if hosts else "done"))
        run_id = (await cur.fetchone())["id"]
        for h, batch in zip(hosts, batches_for(len(hosts), batch_size, canary)):
            args: dict = {}
            if kind == "apply":
                sel = dict(selection)
                if sel.get("mode") == "packages":
                    sel["packages"] = (selection.get("packages") or {}).get(str(h["id"]), [])
                sel["held"] = list(h["held"] or [])
                args = {"selection": sel, "reboot": reboot}
            await conn.execute(
                "INSERT INTO tasks (run_id, host_id, op, args, batch, status) VALUES (%s,%s,%s,%s,%s,%s)",
                (run_id, h["id"], kind, J(args), batch, "queued" if batch == 0 else "waiting"))
        if not hosts:
            await conn.execute("UPDATE runs SET finished_at = NOW(), note = 'No hosts matched' WHERE id = %s",
                               (run_id,))
    await db.notify(TASK_CHANNEL, str(run_id))
    await db.audit(actor, f"Started run #{run_id}: {title} ({len(hosts)} hosts)")
    return run_id


async def queue_scan(host_ids: Iterable[int]) -> int:
    """Queue a scan task for hosts that don't already have one waiting."""
    ids = list(host_ids)
    n = await db.execute(
        """INSERT INTO tasks (host_id, op, status)
           SELECT h.id, 'scan', 'queued' FROM hosts h
            WHERE h.id = ANY(%s)
              AND NOT EXISTS (SELECT 1 FROM tasks t WHERE t.host_id = h.id AND t.op = 'scan'
                                AND t.status IN ('queued', 'running'))""", ids)
    if n:
        await db.notify(TASK_CHANNEL, "scan")
    return n


async def advance_runs() -> None:
    """Move every running run along: open the next batch, stop on failures or a
    closed window, and finish runs whose tasks are all done."""
    for run in await db.fetch("SELECT * FROM runs WHERE status IN ('running', 'paused')"):
        counts = {r["status"]: r["n"] for r in await db.fetch(
            "SELECT status, COUNT(*) AS n FROM tasks WHERE run_id = %s GROUP BY status", run["id"])}
        failed = counts.get("failed", 0)
        active = counts.get("queued", 0) + counts.get("running", 0)
        waiting = counts.get("waiting", 0)
        rid = run["id"]

        if run["max_failures"] and failed >= run["max_failures"] and (waiting or counts.get("queued")):
            await _skip_rest(rid, f"stopped after {failed} failed host{'s' if failed != 1 else ''}")
            await _finish(run, "failed", f"Stopped after {failed} failed host{'s' if failed != 1 else ''}")
            continue

        if run["window_end"] and now() >= run["window_end"] and run["on_window_close"] != "carry_on" \
                and (waiting or counts.get("queued")):
            await _skip_rest(rid, "maintenance window closed")
            if not counts.get("running"):
                await _finish(run, "stopped", "Window closed before every host was done")
            continue

        if active:
            continue
        if waiting and run["status"] == "running":
            nxt = await db.fetchval(
                "SELECT MIN(batch) FROM tasks WHERE run_id = %s AND status = 'waiting'", rid)
            await db.execute("UPDATE tasks SET status = 'queued' WHERE run_id = %s AND batch = %s "
                             "AND status = 'waiting'", rid, nxt)
            await db.execute("UPDATE runs SET current_batch = %s WHERE id = %s", nxt, rid)
            await db.notify(TASK_CHANNEL, str(rid))
            continue
        if not waiting:
            skipped = counts.get("skipped", 0)
            if run["status"] in ("running", "paused"):
                if failed:
                    await _finish(run, "done", f"{failed} host{'s' if failed != 1 else ''} failed")
                elif skipped and run["window_end"] and now() >= run["window_end"]:
                    await _finish(run, "stopped", "Window closed before every host was done")
                else:
                    await _finish(run, "done", None)


async def _skip_rest(run_id: int, why: str) -> None:
    await db.execute("""UPDATE tasks SET status = 'skipped', detail = %s, finished_at = NOW()
                         WHERE run_id = %s AND status IN ('waiting', 'queued')""", why, run_id)


async def _finish(run: dict, status: str, note: Optional[str]) -> None:
    await db.execute("UPDATE runs SET status = %s, note = %s, finished_at = NOW() WHERE id = %s "
                     "AND status IN ('running', 'paused')", status, note, run["id"])
    if run["booking_id"]:
        await db.execute("UPDATE bookings SET status = 'done' WHERE id = %s AND status = 'started'",
                         run["booking_id"])
    log.info("run %s %s%s", run["id"], status, f": {note}" if note else "")


async def abort_run(run_id: int, actor: str) -> None:
    await _skip_rest(run_id, f"aborted by {actor}")
    await db.execute("""UPDATE runs SET status = 'aborted', note = %s, finished_at = NOW()
                         WHERE id = %s AND status IN ('running', 'paused')""", f"Aborted by {actor}", run_id)
    await db.audit(actor, f"Aborted run #{run_id}")


# ─── Policies and bookings ──────────────────────────────────────────────────

async def schedule_tick() -> None:
    t = now()
    for p in await db.fetch("SELECT * FROM policies WHERE enabled"):
        if p["next_run_at"] is None:
            nxt = next_run(p["repeat"], p["at_time"], t, p["weekdays"], p["monthday"])
            await db.execute("UPDATE policies SET next_run_at = %s WHERE id = %s", nxt, p["id"])
            continue
        if p["next_run_at"] > t:
            continue
        window_end = p["next_run_at"] + timedelta(minutes=p["window_minutes"])
        nxt = next_run(p["repeat"], p["at_time"], t, p["weekdays"], p["monthday"])
        # Claim this slot first so two workers can't both start it.
        claimed = await db.execute("UPDATE policies SET next_run_at = %s WHERE id = %s AND next_run_at = %s",
                                   nxt, p["id"], p["next_run_at"])
        if not claimed:
            continue
        if t >= window_end:
            log.warning("policy %s missed its window (worker was down)", p["name"])
            continue
        host_ids = await resolve_target(p["target"])
        if not host_ids:
            continue
        run_id = await create_run(
            kind="apply", title=p["name"], actor="schedule", host_ids=host_ids,
            selection=p["selection"], batch_size=p["batch_size"], batch_percent=p["batch_percent"],
            canary=p["canary"], max_failures=p["max_failures"], reboot=p["reboot"],
            window_end=window_end, policy_id=p["id"])
        await db.execute("UPDATE policies SET last_run_id = %s WHERE id = %s", run_id, p["id"])

    for b in await db.fetch("""SELECT * FROM bookings WHERE status IN ('booked', 'needs_approval')
                                 AND window_start <= NOW()"""):
        if b["window_end"] <= t or (b["needs_approval"] and not b["approved_by"]):
            await db.execute("UPDATE bookings SET status = 'missed' WHERE id = %s", b["id"])
            await db.audit("schedule", f"Booked install '{b['title']}' missed its window"
                           + (" (not approved)" if b["needs_approval"] and not b["approved_by"] else ""))
            continue
        claimed = await db.execute("UPDATE bookings SET status = 'started' WHERE id = %s "
                                   "AND status IN ('booked', 'needs_approval')", b["id"])
        if not claimed:
            continue
        host_ids = await resolve_target(b["target"])
        run_id = await create_run(
            kind="apply", title=b["title"], actor=b["created_by"], host_ids=host_ids,
            selection=b["selection"], batch_size=b["batch_size"], reboot=b["reboot"],
            window_end=b["window_end"], on_window_close=b["on_window_close"], booking_id=b["id"])
        await db.execute("UPDATE bookings SET run_id = %s WHERE id = %s", run_id, b["id"])


# ─── Recording results ──────────────────────────────────────────────────────

async def record_facts(host_id: int, facts: dict) -> None:
    booted = datetime.fromtimestamp(facts["booted_at"], timezone.utc) if facts.get("booted_at") else None
    await db.execute(
        """UPDATE hosts SET os_id = %s, os_version = %s, os_pretty = %s, pkg_family = %s,
                            kernel = %s, boot_id = %s, booted_at = %s, last_seen = NOW(),
                            machine_id = COALESCE(%s, machine_id),
                            address = CASE WHEN mode = 'agent' AND %s <> '' THEN %s ELSE address END
            WHERE id = %s""",
        facts.get("os_id"), facts.get("os_version"), facts.get("os_pretty"), facts.get("family"),
        facts.get("kernel"), facts.get("boot_id"), booted, facts.get("machine_id") or None,
        facts.get("address") or "", facts.get("address") or "", host_id)


async def record_scan(host_id: int, result: dict) -> None:
    if result.get("facts"):
        await record_facts(host_id, result["facts"])
    pending = result.get("pending") or []
    async with db.transaction() as conn:
        await conn.execute("DELETE FROM pending_updates WHERE host_id = %s", (host_id,))
        if pending:
            async with conn.cursor() as cur:
                await cur.executemany(
                    """INSERT INTO pending_updates (host_id, name, arch, current, available, source,
                                                    is_security, is_kernel, kind, severity, advisory)
                       VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s) ON CONFLICT DO NOTHING""",
                    [(host_id, p["name"], p.get("arch") or "", p.get("current"), p["available"],
                      p.get("source") or "", bool(p.get("is_security")), bool(p.get("is_kernel")),
                      p.get("kind") or "bugfix", p.get("severity"), p.get("advisory")) for p in pending])
        await conn.execute(
            """UPDATE hosts SET pending_count = %s, security_count = %s, reboot_required = %s,
                                last_scan_at = NOW(), last_seen = NOW(), last_error = NULL
                WHERE id = %s""",
            (result.get("pending_count", 0), result.get("security_count", 0),
             bool(result.get("reboot_required")), host_id))


async def record_changes(task_id: Optional[int], host_id: int, changes: list[dict]) -> None:
    if not changes:
        return
    async with db.transaction() as conn:
        async with conn.cursor() as cur:
            await cur.executemany(
                "INSERT INTO package_changes (task_id, host_id, name, from_version, to_version) "
                "VALUES (%s,%s,%s,%s,%s)",
                [(task_id, host_id, c["name"], c.get("from"), c.get("to")) for c in changes])


async def append_log(task_id: int, text: str) -> None:
    if text:
        await db.execute("UPDATE tasks SET log = log || %s WHERE id = %s", text, task_id)


async def finish_task(task_id: int, ok: bool, detail: Optional[str], result: Optional[dict] = None) -> None:
    slim = None
    if result is not None:
        slim = {k: v for k, v in result.items() if k not in ("pending", "facts")}
    await db.execute("""UPDATE tasks SET status = %s, detail = %s, result = %s, finished_at = NOW()
                         WHERE id = %s""", "done" if ok else "failed", detail,
                     J(slim) if slim is not None else None, task_id)
    await db.notify(TASK_CHANNEL, "done")
