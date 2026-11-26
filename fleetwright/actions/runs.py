"""Runs: starting them, steering them and reading what happened."""

from __future__ import annotations

from typing import Optional

from .. import db, fleet, gateway
from .core import Principal, action, invalid, not_found

KINDS = {"apply": "Install updates", "reboot": "Reboot", "scan": "Scan", "auto_off": fleet.AUTO_OFF_TITLE,
         "agent_update": "Update agents"}
DEFAULT_TITLES = {"reboot": "Reboot", "scan": "Scan", "auto_off": fleet.AUTO_OFF_TITLE,
                  "agent_update": "Update agents"}


def check_selection(selection: Optional[dict]) -> dict:
    """A selection in the form runs, policies and bookings store (see schema.sql)."""
    sel = dict(selection or {"mode": "all"})
    mode = sel.get("mode", "all")
    if mode not in ("all", "kinds", "packages"):
        raise invalid("selection.mode is all, kinds or packages")
    if mode == "kinds":
        bad = [k for k in sel.get("kinds") or [] if k not in fleet.KINDS]
        if bad:
            raise invalid(f"Unknown kinds: {', '.join(bad)} (use {', '.join(fleet.KINDS)})")
        if not sel.get("kinds") and not sel.get("include"):
            raise invalid("Pick at least one kind of update, or a package to always include.")
        if sel.get("min_severity") and sel["min_severity"] not in fleet.SEVERITIES:
            raise invalid(f"min_severity is one of {', '.join(fleet.SEVERITIES)}")
    return sel


async def pin_picked(picked: dict) -> dict:
    """{host id: [{name, arch?}]} -> {"<host id>": [{name, arch, version}]}, pinned to the versions
    pending now, so a newer release published before the run isn't slipped in."""
    out = {}
    for hid, pkgs in picked.items():
        rows = {(r["name"], r["arch"]): r["available"] for r in await db.fetch(
            "SELECT name, arch, available FROM pending_updates WHERE host_id = %s", int(hid))}
        chosen = []
        for p in pkgs:
            arch = p.get("arch")
            match = [(n, a) for (n, a) in rows if n == p["name"] and (arch is None or a == arch)]
            if not match:
                raise invalid(f"{p['name']} isn't pending on host {hid}")
            for n, a in match:
                chosen.append({"name": n, "arch": a, "version": rows[(n, a)]})
        out[str(int(hid))] = chosen
    return out


@action("runs.start", "operator")
async def start(who: Principal, *, kind: str, target: dict, selection: Optional[dict] = None,
                picked: Optional[dict] = None, title: str = "", batch_size: int = 0, batch_percent: int = 0,
                canary: bool = False, max_failures: int = 0, reboot: str = "never") -> dict:
    """Start a run on the target's hosts: install updates (all, by kind or picked), reboot, scan,
    turn off the hosts' own automatic updates, or update their agents."""
    if kind not in KINDS:
        raise invalid(f"kind is one of {', '.join(KINDS)}")
    if reboot not in fleet.REBOOT_CHOICES:
        raise invalid(f"reboot is one of {', '.join(fleet.REBOOT_CHOICES)}")
    host_ids = await fleet.resolve_target(target or {})
    if picked:
        host_ids = sorted({int(h) for h in picked})
    if not host_ids:
        raise invalid("No hosts match that target.")
    if kind == "agent_update":
        run_id = await gateway.start_agent_update(who.actor, host_ids, title or "Update agents")
        if run_id is None:
            raise invalid("None of those hosts has an agent that can update itself and differs from this "
                          "server's. Agents older than 0.3.0 need reinstalling once.")
        return {"run_id": run_id}
    sel = None
    if kind == "apply":
        if picked:
            sel = {"mode": "packages", "packages": await pin_picked(picked)}
            n = sum(len(v) for v in sel["packages"].values())
            title = title or f"{n} picked update{'s' if n != 1 else ''}"
        else:
            sel = check_selection(selection)
            title = title or fleet.describe_selection(sel)
    run_id = await fleet.create_run(kind=kind, title=(title or DEFAULT_TITLES[kind])[:200], actor=who.actor,
                                    host_ids=host_ids, selection=sel, batch_size=max(0, batch_size),
                                    batch_percent=max(0, min(100, batch_percent)), canary=canary,
                                    max_failures=max(0, max_failures), reboot=reboot)
    return {"run_id": run_id}


@action("agents.update_all", "admin")
async def update_all_agents(who: Principal) -> dict:
    """Update every agent that can update itself and differs from this server's, as one careful run."""
    ids = [r["id"] for r in await db.fetch("SELECT id FROM hosts WHERE mode = 'agent'")]
    run_id = await gateway.start_agent_update(who.actor, ids)
    if run_id is None:
        raise invalid("Every agent that can update itself already matches this server.")
    return {"run_id": run_id}


async def _run(run_id: int) -> dict:
    run = await db.fetchone("SELECT * FROM runs WHERE id = %s", run_id)
    if not run:
        raise not_found("run")
    return run


@action("runs.list", "viewer")
async def list_runs(who: Principal, *, limit: int = 50, offset: int = 0, before_id: Optional[int] = None,
                    status: str = "") -> dict:
    """Runs, newest first (running and paused ones first on the page), with their host counts."""
    order = "r.id DESC" if before_id is not None else "(r.status IN ('running','paused')) DESC, r.id DESC"
    rows = await db.fetch(f"""SELECT r.*, COUNT(t.id) AS total,
                                     COUNT(t.id) FILTER (WHERE t.status IN ('done','failed','skipped')) AS finished,
                                     COUNT(t.id) FILTER (WHERE t.status = 'failed') AS failed,
                                     COUNT(t.id) FILTER (WHERE t.status = 'done') AS ok
                                FROM runs r LEFT JOIN tasks t ON t.run_id = r.id
                               WHERE (%s::int IS NULL OR r.id < %s) AND (%s = '' OR r.status = %s)
                               GROUP BY r.id ORDER BY {order} LIMIT %s OFFSET %s""",
                          before_id, before_id, status, status, limit, offset)
    return {"runs": rows}


@action("runs.get", "viewer")
async def get_run(who: Principal, run_id: int) -> dict:
    """A run with its batches and every host's task."""
    run = await _run(run_id)
    run["batches"] = await db.fetch("""SELECT batch, COUNT(*) AS hosts,
                                              COUNT(*) FILTER (WHERE status = 'done') AS done,
                                              COUNT(*) FILTER (WHERE status = 'failed') AS failed,
                                              COUNT(*) FILTER (WHERE status = 'running') AS running,
                                              COUNT(*) FILTER (WHERE status = 'skipped') AS skipped,
                                              COUNT(*) FILTER (WHERE status IN ('waiting','queued')) AS waiting
                                         FROM tasks WHERE run_id = %s GROUP BY batch ORDER BY batch""", run_id)
    run["tasks"] = await db.fetch("""SELECT t.id, t.host_id, h.name AS host, t.op, t.batch, t.status, t.detail,
                                            t.started_at, t.finished_at,
                                            (SELECT COUNT(*) FROM package_changes c WHERE c.task_id = t.id) AS changed
                                       FROM tasks t JOIN hosts h ON h.id = t.host_id
                                      WHERE t.run_id = %s ORDER BY t.batch, h.name""", run_id)
    run["packages_changed"] = await db.fetchval("""SELECT COUNT(*) FROM package_changes c JOIN tasks t
                                                    ON t.id = c.task_id WHERE t.run_id = %s""", run_id)
    return run


@action("runs.task", "viewer")
async def get_task(who: Principal, task_id: int) -> dict:
    """One host's task in a run (or a scan): its status, full log, result and package changes."""
    t = await db.fetchone("""SELECT t.*, h.name AS host FROM tasks t JOIN hosts h ON h.id = t.host_id
                              WHERE t.id = %s""", task_id)
    if not t:
        raise not_found("task")
    t.pop("claimed_by", None)
    t["changes"] = await db.fetch("SELECT name, from_version, to_version, at FROM package_changes "
                                  "WHERE task_id = %s ORDER BY name", task_id)
    return t


@action("runs.pause", "operator")
async def pause(who: Principal, run_id: int) -> dict:
    """Pause a run: the batch that's running finishes, then nothing new starts."""
    run = await _run(run_id)
    if run["status"] != "running":
        raise invalid(f"Run #{run_id} is {run['status']}, not running.")
    await db.execute("UPDATE runs SET status = 'paused' WHERE id = %s", run_id)
    await db.audit(who.actor, f"Paused run #{run_id}")
    return {"status": "paused"}


@action("runs.resume", "operator")
async def resume(who: Principal, run_id: int) -> dict:
    """Resume a paused run."""
    run = await _run(run_id)
    if run["status"] != "paused":
        raise invalid(f"Run #{run_id} is {run['status']}, not paused.")
    await db.execute("UPDATE runs SET status = 'running' WHERE id = %s", run_id)
    await db.audit(who.actor, f"Resumed run #{run_id}")
    return {"status": "running"}


@action("runs.abort", "operator")
async def abort(who: Principal, run_id: int) -> dict:
    """Abort a run: hosts already running finish their current step, the rest are skipped."""
    await _run(run_id)
    await fleet.abort_run(run_id, who.actor)
    return {"status": "aborted"}


@action("runs.retry", "operator")
async def retry(who: Principal, run_id: int) -> dict:
    """Start a new run, with the same settings, on just the hosts that failed in this one."""
    run = await _run(run_id)
    hosts = [r["host_id"] for r in await db.fetch(
        "SELECT host_id FROM tasks WHERE run_id = %s AND status = 'failed'", run_id)]
    if not hosts:
        raise invalid(f"No host failed in run #{run_id}.")
    new_id = await fleet.create_run(kind=run["kind"], title=run["title"].removesuffix(" (retry)") + " (retry)",
                                    actor=who.actor, host_ids=hosts, selection=run["selection"],
                                    reboot=run["reboot"], batch_size=run["batch_size"],
                                    canary=run["canary"], max_failures=run["max_failures"],
                                    window_end=run["window_end"], on_window_close=run["on_window_close"])
    return {"run_id": new_id}
