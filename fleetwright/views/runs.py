"""Runs: the list, one run with its batches and live output, and its controls."""

from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import HTMLResponse

from .. import db, fleet
from ..webcommon import flash, form_data, redirect, render, require

router = APIRouter()


@router.get("/runs", response_class=HTMLResponse)
async def run_list(request: Request, page: int = 1):
    per = 50
    page = max(1, page)
    rows = await db.fetch("""SELECT r.*, COUNT(t.id) AS total,
                                    COUNT(t.id) FILTER (WHERE t.status IN ('done','failed','skipped')) AS finished,
                                    COUNT(t.id) FILTER (WHERE t.status = 'failed') AS failed,
                                    COUNT(t.id) FILTER (WHERE t.status = 'done') AS ok
                               FROM runs r LEFT JOIN tasks t ON t.run_id = r.id
                              GROUP BY r.id ORDER BY (r.status IN ('running','paused')) DESC, r.id DESC
                              LIMIT %s OFFSET %s""", per + 1, (page - 1) * per)
    return render(request, "runs.html", runs=rows[:per], page=page, more=len(rows) > per)


async def _run_state(run_id: int, task_id: Optional[int], batch: Optional[int]) -> dict:
    run = await db.fetchone("SELECT * FROM runs WHERE id = %s", run_id)
    if not run:
        raise HTTPException(404, "No such run")
    batches = await db.fetch("""SELECT batch, COUNT(*) AS n,
                                       COUNT(*) FILTER (WHERE status = 'done') AS ok,
                                       COUNT(*) FILTER (WHERE status = 'failed') AS failed,
                                       COUNT(*) FILTER (WHERE status = 'running') AS running,
                                       COUNT(*) FILTER (WHERE status = 'skipped') AS skipped,
                                       COUNT(*) FILTER (WHERE status = 'waiting') AS waiting,
                                       COUNT(*) FILTER (WHERE status = 'queued') AS queued
                                  FROM tasks WHERE run_id = %s GROUP BY batch ORDER BY batch""", run_id)
    totals = {k: sum(b[k] for b in batches) for k in ("n", "ok", "failed", "running", "skipped", "waiting", "queued")}
    if batch is None:
        batch = run["current_batch"]
        live = [b["batch"] for b in batches if b["running"] or b["queued"]]
        if live:
            batch = live[0]
    tasks = await db.fetch("""SELECT t.id, t.status, t.detail, t.op, t.started_at, t.finished_at, t.batch,
                                     h.name, h.id AS host_id, h.mode,
                                     (SELECT COUNT(*) FROM package_changes c WHERE c.task_id = t.id) AS changed
                                FROM tasks t JOIN hosts h ON h.id = t.host_id
                               WHERE t.run_id = %s AND t.batch = %s ORDER BY h.name""", run_id, batch)
    if task_id is None:
        running = [t for t in tasks if t["status"] == "running"]
        pick = running[0] if running else (next((t for t in tasks if t["status"] == "failed"), None)
                                           or (tasks[0] if tasks else None))
        task_id = pick["id"] if pick else None
    task = await db.fetchone("""SELECT t.*, h.name, h.mode FROM tasks t JOIN hosts h ON h.id = t.host_id
                                 WHERE t.id = %s AND t.run_id = %s""", task_id, run_id) if task_id else None
    changes = await db.fetch("SELECT * FROM package_changes WHERE task_id = %s ORDER BY name", task_id) \
        if task_id else []
    pkg_total = await db.fetchval("""SELECT COUNT(*) FROM package_changes c JOIN tasks t ON t.id = c.task_id
                                      WHERE t.run_id = %s""", run_id)
    return {"run": run, "batches": batches, "totals": totals, "batch": batch, "tasks": tasks, "task": task,
            "changes": changes, "pkg_total": pkg_total, "batch_label": _batch_label(run, batches)}


def _batch_label(run: dict, batches: list[dict]):
    def label(b: int) -> str:
        if run["canary"] and b == 0 and len(batches) > 1:
            return "Canary"
        return f"Batch {b if run['canary'] else b + 1}" if len(batches) > 1 else "All hosts"
    return label


@router.get("/runs/{run_id}", response_class=HTMLResponse)
async def run_page(request: Request, run_id: int, task: Optional[int] = None, batch: Optional[int] = None):
    state = await _run_state(run_id, task, batch)
    return render(request, "run.html", target=await _target_text(state["run"]), **state)


@router.get("/runs/{run_id}/live", response_class=HTMLResponse)
async def run_live(request: Request, run_id: int, task: Optional[int] = None, batch: Optional[int] = None):
    state = await _run_state(run_id, task, batch)
    return render(request, "run_live.html", **state)


async def _target_text(run: dict) -> str:
    if run["policy_id"]:
        return "Auto-install policy"
    if run["booking_id"]:
        return "Booked install"
    return f"Started by {run['created_by']}"


@router.post("/runs/{run_id}/control")
async def run_control(request: Request, run_id: int):
    form = await form_data(request)
    u = require(request, "operator")
    action = form.get("action")
    run = await db.fetchone("SELECT * FROM runs WHERE id = %s", run_id)
    if not run:
        raise HTTPException(404)
    if action == "abort":
        await fleet.abort_run(run_id, u["name"])
        flash(request, "Aborted. Hosts already running finish their current step.", "info")
    elif action == "pause" and run["status"] == "running":
        await db.execute("UPDATE runs SET status = 'paused' WHERE id = %s", run_id)
        await db.audit(u["name"], f"Paused run #{run_id}")
        flash(request, "Paused: the batch that's running finishes, then nothing new starts.", "info")
    elif action == "resume" and run["status"] == "paused":
        await db.execute("UPDATE runs SET status = 'running' WHERE id = %s", run_id)
        await db.audit(u["name"], f"Resumed run #{run_id}")
        flash(request, "Resumed.")
    elif action == "retry_failed":
        hosts = [r["host_id"] for r in await db.fetch(
            "SELECT host_id FROM tasks WHERE run_id = %s AND status = 'failed'", run_id)]
        if hosts:
            new_id = await fleet.create_run(kind=run["kind"], title=f"{run['title']} (retry)", actor=u["name"],
                                            host_ids=hosts, selection=run["selection"], reboot=run["reboot"],
                                            batch_size=run["batch_size"], max_failures=run["max_failures"])
            return redirect(f"/runs/{new_id}")
    return redirect(f"/runs/{run_id}")
