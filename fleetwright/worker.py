"""
worker.py
~~~~~~~~~
The background process. Runs as many copies as you like; they share the
work through Postgres.

- claims queued tasks for agentless (SSH) hosts and runs them, up to
  FLEETWRIGHT_SSH_CONCURRENCY at once per worker
- starts auto-install policies and booked installs when they're due, and
  moves runs from batch to batch (one worker at a time does this)
- queues a scan for SSH hosts not scanned for FLEETWRIGHT_SCAN_INTERVAL_MIN
- fails tasks that have been running far too long (a worker that died)
"""

from __future__ import annotations

import asyncio
import logging
import signal
import time

import psycopg

from . import config, db, fleet, sshrun

log = logging.getLogger("fleetwright.worker")

SCHEDULER_LOCK = 42424243


class TaskLog:
    """Collects a task's output and appends it to the row about once a second."""

    def __init__(self, task_id: int):
        self.task_id = task_id
        self.buf: list[str] = []
        self.last = time.monotonic()

    async def line(self, text: str) -> None:
        self.buf.append(f"{time.strftime('%H:%M:%S', time.gmtime())} {text}\n")
        if time.monotonic() - self.last > 1.0 or len(self.buf) > 200:
            await self.flush()

    async def flush(self) -> None:
        if self.buf:
            text, self.buf = "".join(self.buf), []
            await fleet.append_log(self.task_id, text)
        self.last = time.monotonic()


def wants_reboot(policy: str, result: dict) -> bool:
    return policy == "always" or (policy == "if_needed" and bool(result.get("reboot_required")))


def apply_detail(result: dict) -> str:
    n = len(result.get("changes") or [])
    if not result.get("planned"):
        return "Nothing to install"
    return f"{n} package{'s' if n != 1 else ''} changed"


async def record_apply(task: dict, result: dict) -> None:
    await fleet.record_scan(task["host_id"], result)
    await fleet.record_changes(task["id"], task["host_id"], result.get("changes") or [])


async def _reboot_ssh(host: dict, tlog: TaskLog) -> tuple[bool, str]:
    before = await sshrun.boot_id(host)
    res = await sshrun.run_pkgops(host, "reboot", None, tlog.line)
    if not res.get("ok"):
        return False, res.get("error", "reboot failed")
    await tlog.line("waiting for the host to come back…")
    await tlog.flush()
    await asyncio.sleep(20)
    deadline = time.monotonic() + config.REBOOT_WAIT
    while time.monotonic() < deadline:
        now_id = await sshrun.boot_id(host)
        if now_id and now_id != before:
            await tlog.line("host is back")
            scan = await sshrun.run_pkgops(host, "scan", None, tlog.line)
            if scan.get("ok"):
                await fleet.record_scan(host["id"], scan)
            return True, "rebooted"
        await asyncio.sleep(10)
    return False, f"didn't come back within {config.REBOOT_WAIT // 60} min of rebooting"


async def run_ssh_task(task: dict) -> None:
    host = await db.fetchone("SELECT * FROM hosts WHERE id = %s", task["host_id"])
    tlog = TaskLog(task["id"])
    ok, detail, result = False, None, None
    try:
        if task["op"] == "scan":
            result = await sshrun.run_pkgops(host, "scan", None, tlog.line)
            ok = bool(result.get("ok"))
            if ok:
                await fleet.record_scan(host["id"], result)
                detail = f"{result.get('pending_count', 0)} pending"
        elif task["op"] == "apply":
            args = task["args"] or {}
            await tlog.line(f"▸ selection {fleet.describe_selection(args.get('selection') or {})}")
            result = await sshrun.run_pkgops(host, "apply", args.get("selection") or {"mode": "all"}, tlog.line)
            ok = bool(result.get("ok"))
            if ok:
                await record_apply(task, result)
                detail = apply_detail(result)
                if wants_reboot(args.get("reboot", "never"), result):
                    await tlog.line("▸ reboot")
                    ok, why = await _reboot_ssh(host, tlog)
                    detail += f", {why}"
        elif task["op"] == "reboot":
            ok, detail = await _reboot_ssh(host, tlog)
        else:
            detail = f"unknown operation {task['op']}"
        if result is not None and not result.get("ok"):
            detail = (result.get("error") or "failed").strip()
    except (sshrun.SSHFailure, sshrun.HostKeyMismatch) as e:
        detail = str(e)
        await tlog.line(f"✗ {e}")
    except Exception as e:  # noqa: BLE001 - a task must always finish
        log.exception("task %s crashed", task["id"])
        detail = f"{type(e).__name__}: {e}"
        await tlog.line(f"✗ {detail}")
    await tlog.flush()
    if ok:
        await tlog.line("✓ done")
    else:
        await db.execute("UPDATE hosts SET last_error = %s WHERE id = %s", (detail or "")[:500], host["id"])
    await tlog.flush()
    await fleet.finish_task(task["id"], ok, (detail or "")[:500], result)


CLAIM_SQL = """
UPDATE tasks SET status = 'running', claimed_by = %s, started_at = NOW()
 WHERE id IN (
    SELECT t.id FROM tasks t JOIN hosts h ON h.id = t.host_id
     WHERE t.status = 'queued' AND h.mode = 'ssh'
       AND t.id = (SELECT MIN(q.id) FROM tasks q WHERE q.host_id = t.host_id AND q.status = 'queued')
       AND NOT EXISTS (SELECT 1 FROM tasks r WHERE r.host_id = t.host_id AND r.status = 'running')
     ORDER BY t.id
     LIMIT %s
       FOR UPDATE OF t SKIP LOCKED)
RETURNING *"""


class Worker:
    def __init__(self) -> None:
        self.inflight: set[asyncio.Task] = set()
        self.wake = asyncio.Event()
        self.stopping = False

    async def claim(self) -> None:
        room = config.SSH_CONCURRENCY - len(self.inflight)
        if room <= 0:
            return
        for task in await db.fetch(CLAIM_SQL, config.WORKER_NAME, room):
            t = asyncio.create_task(run_ssh_task(task))
            self.inflight.add(t)
            t.add_done_callback(lambda done: (self.inflight.discard(done), self.wake.set()))

    async def listen(self) -> None:
        while not self.stopping:
            try:
                async with await psycopg.AsyncConnection.connect(config.DATABASE_URL, autocommit=True) as conn:
                    await conn.execute(f"LISTEN {fleet.TASK_CHANNEL}")
                    async for _ in conn.notifies():
                        self.wake.set()
            except (psycopg.Error, OSError) as e:
                log.warning("LISTEN connection lost (%s); retrying", e)
                await asyncio.sleep(5)

    async def housekeeping(self) -> None:
        last_scan_check = 0.0
        while not self.stopping:
            try:
                async with db.pool().connection() as conn:
                    got = (await (await conn.execute("SELECT pg_try_advisory_lock(%s) AS ok",
                                                     (SCHEDULER_LOCK,))).fetchone())["ok"]
                    if got:
                        try:
                            await fleet.schedule_tick()
                            await fleet.advance_runs()
                            if time.monotonic() - last_scan_check > 60:
                                last_scan_check = time.monotonic()
                                await self.due_scans()
                                await self.sweep()
                        finally:
                            await conn.execute("SELECT pg_advisory_unlock(%s)", (SCHEDULER_LOCK,))
            except Exception:  # noqa: BLE001
                log.exception("housekeeping failed")
            await asyncio.sleep(5)

    async def due_scans(self) -> None:
        rows = await db.fetch(
            """SELECT id FROM hosts WHERE mode = 'ssh' AND credential_id IS NOT NULL
                 AND (last_scan_at IS NULL OR last_scan_at < NOW() - make_interval(mins => %s))
               ORDER BY last_scan_at NULLS FIRST LIMIT 500""", config.SCAN_INTERVAL_MIN)
        if rows:
            n = await fleet.queue_scan([r["id"] for r in rows])
            if n:
                log.info("queued %d scheduled scans", n)

    async def sweep(self) -> None:
        n = await db.execute(
            """UPDATE tasks SET status = 'failed', finished_at = NOW(),
                      detail = 'Timed out: no result within the task time limit'
                WHERE status = 'running' AND started_at < NOW() - make_interval(secs => %s)""",
            config.TASK_TIMEOUT + config.REBOOT_WAIT)
        if n:
            log.warning("failed %d stuck tasks", n)
        # An agent host that was told to reboot and hasn't reconnected since.
        n = await db.execute(
            """UPDATE tasks SET status = 'failed', finished_at = NOW(),
                      detail = 'Rebooted but the agent hadn''t reconnected within the reboot wait'
                WHERE status = 'running' AND detail = 'rebooting'
                  AND (result->>'reboot_started')::timestamptz < NOW() - make_interval(secs => %s)""",
            config.REBOOT_WAIT)
        if n:
            log.warning("%d agent hosts didn't come back from a reboot", n)
            await db.notify(fleet.TASK_CHANNEL, "done")
        await db.execute("DELETE FROM tasks WHERE run_id IS NULL AND op = 'scan' AND status IN ('done','failed') "
                         "AND finished_at < NOW() - INTERVAL '7 days'")
        await db.execute("DELETE FROM audit_log WHERE at < NOW() - make_interval(days => %s)",
                         config.LOG_RETENTION_DAYS * 4)

    async def recover(self) -> None:
        """Tasks this worker name held when it last stopped can't still be running."""
        n = await db.execute("""UPDATE tasks SET status = 'failed', finished_at = NOW(),
                                       detail = 'The worker restarted while this was running'
                                 WHERE status = 'running' AND claimed_by = %s""", config.WORKER_NAME)
        if n:
            log.warning("marked %d interrupted tasks failed", n)

    async def main(self) -> None:
        await db.open_pool(max_size=max(10, config.SSH_CONCURRENCY // 2))
        await db.migrate()
        await self.recover()
        bg = [asyncio.create_task(self.listen()), asyncio.create_task(self.housekeeping())]
        log.info("worker %s ready (up to %d SSH tasks at once)", config.WORKER_NAME, config.SSH_CONCURRENCY)
        while not self.stopping:
            try:
                await self.claim()
            except Exception:  # noqa: BLE001
                log.exception("claiming tasks failed")
            self.wake.clear()
            try:
                await asyncio.wait_for(self.wake.wait(), timeout=5)
            except asyncio.TimeoutError:
                pass
        for t in bg:
            t.cancel()
        if self.inflight:
            log.info("waiting for %d running tasks", len(self.inflight))
            await asyncio.gather(*self.inflight, return_exceptions=True)
        await db.close_pool()


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    logging.getLogger("asyncssh").setLevel(logging.WARNING)
    w = Worker()
    loop = asyncio.new_event_loop()

    def stop() -> None:
        log.info("stopping: no new tasks; finishing running ones")
        w.stopping = True
        w.wake.set()

    for sig in (signal.SIGTERM, signal.SIGINT):
        loop.add_signal_handler(sig, stop)
    loop.run_until_complete(w.main())


if __name__ == "__main__":
    main()
