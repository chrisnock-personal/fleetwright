"""Schedules: auto-install policies, one-off booked installs and the week ahead."""

from __future__ import annotations

from datetime import datetime, time, timedelta, timezone
from typing import Optional

from fastapi import APIRouter, HTTPException, Query, Request
from fastapi.responses import HTMLResponse

from .. import db, fleet, pkgops
from ..db import J
from ..schedule import WEEKDAYS, describe, next_run
from ..webcommon import as_list, flash, form_data, redirect, render, require, split_words

router = APIRouter()


def _week_strip(policies: list[dict], bookings: list[dict]) -> list[dict]:
    start = datetime.now(timezone.utc).replace(hour=0, minute=0, second=0, microsecond=0)
    days = [{"date": start + timedelta(days=i), "slots": []} for i in range(7)]
    end = start + timedelta(days=7)
    for p in policies:
        if not p["enabled"]:
            continue
        t = start - timedelta(seconds=1)
        for _ in range(8):
            t = next_run(p["repeat"], p["at_time"], t, p["weekdays"], p["monthday"])
            if t >= end:
                break
            days[(t - start).days]["slots"].append({"kind": "auto", "title": p["name"], "at": t,
                                                    "href": f"/schedules/policies/{p['id']}"})
    for b in bookings:
        if b["status"] in ("booked", "needs_approval", "started") and start <= b["window_start"] < end:
            days[(b["window_start"] - start).days]["slots"].append(
                {"kind": "once", "title": b["title"], "at": b["window_start"], "until": b["window_end"],
                 "href": f"/runs/{b['run_id']}" if b["run_id"] else "#bookings"})
    for d in days:
        d["slots"].sort(key=lambda s: s["at"])
    return days


@router.get("/schedules", response_class=HTMLResponse)
async def schedules(request: Request):
    policies = await db.fetch("SELECT * FROM policies ORDER BY enabled DESC, name")
    for p in policies:
        p["target_text"] = await fleet.describe_target(p["target"])
        p["when_text"] = describe(p)
    bookings = await db.fetch("""SELECT * FROM bookings
                                  WHERE status IN ('booked','needs_approval','started')
                                     OR window_end > NOW() - INTERVAL '14 days'
                                  ORDER BY (status IN ('booked','needs_approval','started')) DESC,
                                           window_start DESC LIMIT 50""")
    for b in bookings:
        b["target_text"] = await fleet.describe_target(b["target"])
    return render(request, "schedules.html", policies=policies, bookings=bookings,
                  week=_week_strip(policies, bookings),
                  on_count=sum(1 for p in policies if p["enabled"]),
                  booked=sum(1 for b in bookings if b["status"] in ("booked", "needs_approval")))


# ─── Policies ───────────────────────────────────────────────────────────────

NEW_POLICY = {"id": None, "name": "", "enabled": False, "target": {"groups": [], "tags": [], "exclude_tags": []},
              "selection": {"mode": "kinds", "kinds": ["security"], "min_severity": "", "include": [], "exclude": []},
              "repeat": "daily", "weekdays": [6], "monthday": 1, "at_time": time(2, 0), "window_minutes": 120,
              "batch_size": 0, "batch_percent": 10, "canary": False, "max_failures": 2, "reboot": "if_needed"}


async def preview(target: dict, selection: dict) -> dict:
    """How many updates the policy would install right now, from the last scans."""
    host_ids = await fleet.resolve_target(target)
    if not host_ids:
        return {"hosts": 0, "updates": 0, "affected": 0, "reboot_hosts": 0}
    rows = await db.fetch("""SELECT p.*, h.held FROM pending_updates p JOIN hosts h ON h.id = p.host_id
                              WHERE p.host_id = ANY(%s)""", host_ids)
    by_host: dict[int, list] = {}
    for r in rows:
        by_host.setdefault(r["host_id"], []).append(r)
    updates = affected = kernel_hosts = 0
    for hid, pend in by_host.items():
        chosen, _ = pkgops.select(pend, selection, pend[0]["held"] or [])
        if chosen:
            affected += 1
            updates += len(chosen)
            kernel_hosts += any(p["is_kernel"] for p in chosen)
    already = await db.fetchval("SELECT COUNT(*) FROM hosts WHERE id = ANY(%s) AND reboot_required", host_ids)
    return {"hosts": len(host_ids), "updates": updates, "affected": affected, "reboot_hosts": kernel_hosts + already}


async def _policy_page(request: Request, p: dict, errors: Optional[list] = None, status: int = 200):
    groups = await db.fetch("SELECT id, name FROM groups ORDER BY name")
    tags = [r["tag"] for r in await db.fetch("SELECT DISTINCT unnest(tags) AS tag FROM hosts ORDER BY 1")]
    runs = await db.fetch("SELECT * FROM runs WHERE policy_id = %s ORDER BY id DESC LIMIT 8", p["id"]) \
        if p.get("id") else []
    return render(request, "policy.html", p=p, groups=groups, tags=tags, weekdays=WEEKDAYS, errors=errors or [],
                  preview=await preview(p["target"], p["selection"]), runs=runs, http_status=status,
                  severities=fleet.SEVERITIES, kinds=fleet.KINDS)


@router.get("/schedules/policies/new", response_class=HTMLResponse)
async def policy_new(request: Request):
    require(request, "operator")
    return await _policy_page(request, dict(NEW_POLICY))


@router.get("/schedules/policies/{pid}", response_class=HTMLResponse)
async def policy_edit(request: Request, pid: int):
    p = await db.fetchone("SELECT * FROM policies WHERE id = %s", pid)
    if not p:
        raise HTTPException(404, "No such policy")
    return await _policy_page(request, p)


def _int(value, default: int, lo: int, hi: int) -> int:
    try:
        return max(lo, min(hi, int(value)))
    except (TypeError, ValueError):
        return default


def policy_from_form(form: dict) -> tuple[dict, list[str]]:
    errors = []
    kinds = [k for k in as_list(form.get("kinds")) if k in fleet.KINDS]
    what = form.get("what", "kinds")
    selection = {"mode": "all"} if what == "all" else {
        "mode": "kinds", "kinds": kinds, "min_severity": form.get("min_severity") or "",
        "include": split_words(form.get("include"))}
    selection["exclude"] = split_words(form.get("exclude"))
    if selection["mode"] == "kinds" and not kinds and not selection["include"]:
        errors.append("Pick at least one kind of update, or a package to always include.")
    target = {"all": form.get("all_hosts") == "1",
              "groups": [int(g) for g in as_list(form.get("groups")) if g.isdigit()],
              "tags": split_words(form.get("tags")), "exclude_tags": split_words(form.get("exclude_tags"))}
    if not (target["all"] or target["groups"] or target["tags"]):
        errors.append("Choose which hosts it applies to: all, some groups or some tags.")
    try:
        hh, mm = str(form.get("at_time", "02:00")).split(":")[:2]
        at = time(int(hh), int(mm))
    except ValueError:
        at = time(2, 0)
        errors.append("The start time should look like 02:00.")
    batch_mode = form.get("batch_mode", "all")
    name = str(form.get("name", "")).strip()
    if not name:
        errors.append("Give the policy a name.")
    repeat = form.get("repeat") if form.get("repeat") in ("daily", "weekly", "monthly") else "daily"
    weekdays = sorted({int(d) for d in as_list(form.get("weekdays")) if d.isdigit() and int(d) < 7})
    if repeat == "weekly" and not weekdays:
        errors.append("Pick at least one day of the week.")
    return {
        "name": name, "enabled": form.get("enabled") == "1", "target": target, "selection": selection,
        "repeat": repeat, "weekdays": weekdays, "monthday": _int(form.get("monthday"), 1, 1, 28), "at_time": at,
        "window_minutes": _int(form.get("window_minutes"), 120, 15, 24 * 60),
        "batch_size": _int(form.get("batch_size"), 10, 1, 100000) if batch_mode == "count" else 0,
        "batch_percent": _int(form.get("batch_percent"), 10, 1, 100) if batch_mode == "percent" else 0,
        "canary": form.get("canary") == "1", "max_failures": _int(form.get("max_failures"), 2, 0, 100000),
        "reboot": form.get("reboot") if form.get("reboot") in fleet.REBOOT_CHOICES else "if_needed",
    }, errors


@router.post("/schedules/policies/save")
async def policy_save(request: Request):
    form = await form_data(request)
    u = require(request, "operator")
    pid = int(form["id"]) if str(form.get("id", "")).isdigit() else None
    p, errors = policy_from_form(form)
    if errors:
        return await _policy_page(request, {**p, "id": pid}, errors, 400)
    nxt = next_run(p["repeat"], p["at_time"], datetime.now(timezone.utc), p["weekdays"], p["monthday"])
    cols = ["name", "enabled", "target", "selection", "repeat", "weekdays", "monthday", "at_time",
            "window_minutes", "batch_size", "batch_percent", "canary", "max_failures", "reboot"]
    vals = [J(p[c]) if c in ("target", "selection") else p[c] for c in cols]
    try:
        if pid:
            await db.execute(f"UPDATE policies SET {', '.join(c + ' = %s' for c in cols)}, next_run_at = %s "
                             "WHERE id = %s", *vals, nxt, pid)
        else:
            pid = await db.fetchval(f"INSERT INTO policies ({', '.join(cols)}, next_run_at, created_by) "
                                    f"VALUES ({', '.join(['%s'] * len(cols))}, %s, %s) RETURNING id",
                                    *vals, nxt, u["name"])
    except Exception as e:  # unique name
        if "unique" in str(e).lower():
            return await _policy_page(request, {**p, "id": pid}, ["Another policy already has that name."], 400)
        raise
    await db.audit(u["name"], f"Saved policy {p['name']} ({'on' if p['enabled'] else 'off'})")
    flash(request, f"Saved. {'Next run ' + nxt.strftime('%a %d %b %H:%M') + ' UTC.' if p['enabled'] else 'It is off.'}")
    return redirect(f"/schedules/policies/{pid}")


@router.post("/schedules/policies/{pid}/action")
async def policy_action(request: Request, pid: int):
    form = await form_data(request)
    u = require(request, "operator")
    p = await db.fetchone("SELECT * FROM policies WHERE id = %s", pid)
    if not p:
        raise HTTPException(404)
    action = form.get("action")
    if action == "toggle":
        on = not p["enabled"]
        nxt = next_run(p["repeat"], p["at_time"], datetime.now(timezone.utc), p["weekdays"], p["monthday"])
        await db.execute("UPDATE policies SET enabled = %s, next_run_at = %s WHERE id = %s", on, nxt, pid)
        await db.audit(u["name"], f"Turned policy {p['name']} {'on' if on else 'off'}")
        flash(request, f"{p['name']} is {'on' if on else 'off'}.")
        return redirect(form.get("back") or "/schedules")
    if action == "run_now":
        hosts = await fleet.resolve_target(p["target"])
        run_id = await fleet.create_run(
            kind="apply", title=f"{p['name']} (run by hand)", actor=u["name"], host_ids=hosts,
            selection=p["selection"], batch_size=p["batch_size"], batch_percent=p["batch_percent"],
            canary=p["canary"], max_failures=p["max_failures"], reboot=p["reboot"], policy_id=pid)
        return redirect(f"/runs/{run_id}")
    if action == "delete":
        await db.execute("DELETE FROM policies WHERE id = %s", pid)
        await db.audit(u["name"], f"Deleted policy {p['name']}")
        flash(request, f"Deleted {p['name']}.")
        return redirect("/schedules")
    raise HTTPException(400, "Unknown action")


# ─── Booked installs ────────────────────────────────────────────────────────

def _parse_local(value: str) -> Optional[datetime]:
    try:
        return datetime.fromisoformat(value.strip()).replace(tzinfo=timezone.utc)
    except (ValueError, AttributeError):
        return None


@router.get("/schedules/book", response_class=HTMLResponse)
async def book_page(request: Request, host: list[int] = Query(default=[]), pinned: int = 0):
    require(request, "operator")
    ids = host or []
    hosts = await db.fetch("SELECT id, name FROM hosts WHERE id = ANY(%s) ORDER BY name", ids)
    pins = request.session.get("book_pins") if pinned else None
    start = (datetime.now(timezone.utc) + timedelta(hours=1)).replace(minute=0, second=0, microsecond=0)
    form = {"window_start": start.strftime("%Y-%m-%dT%H:%M"),
            "window_end": (start + timedelta(hours=2)).strftime("%Y-%m-%dT%H:%M"),
            "what": "packages" if pins else "kinds", "kinds": ["security"], "batch_size": "1",
            "reboot": "if_needed", "on_window_close": "finish_started"}
    return await _book_render(request, hosts, pins, form, [])


async def _book_render(request, hosts, pins, form, errors, status=200):
    groups = await db.fetch("SELECT id, name FROM groups ORDER BY name")
    all_hosts = await db.fetch("SELECT id, name FROM hosts ORDER BY name LIMIT 2000")
    pin_rows = []
    for hid, pkgs in (pins or {}).items():
        for p in pkgs:
            pin_rows.append(p)
    return render(request, "book.html", hosts=hosts, pins=pins, pin_rows=pin_rows, form=form, errors=errors,
                  groups=groups, all_hosts=all_hosts, kinds=fleet.KINDS, severities=fleet.SEVERITIES,
                  http_status=status)


@router.post("/schedules/book")
async def book(request: Request):
    form = await form_data(request)
    u = require(request, "operator")
    host_ids = [int(h) for h in as_list(form.get("hosts")) if h.isdigit()]
    target = {"hosts": host_ids, "groups": [int(g) for g in as_list(form.get("groups")) if g.isdigit()],
              "tags": split_words(form.get("tags"))}
    errors = []
    pins = request.session.get("book_pins") if form.get("what") == "packages" else None
    if form.get("what") == "packages" and pins:
        selection = {"mode": "packages", "packages": {k: v for k, v in pins.items() if int(k) in host_ids}}
    elif form.get("what") == "all":
        selection = {"mode": "all"}
    else:
        kinds = [k for k in as_list(form.get("kinds")) if k in fleet.KINDS]
        if not kinds:
            errors.append("Pick at least one kind of update.")
        selection = {"mode": "kinds", "kinds": kinds, "min_severity": form.get("min_severity") or ""}
    selection["exclude"] = split_words(form.get("exclude"))
    ws, we = _parse_local(str(form.get("window_start", ""))), _parse_local(str(form.get("window_end", "")))
    now = datetime.now(timezone.utc)
    if not ws or not we:
        errors.append("Enter when the window opens and closes.")
    elif we <= ws:
        errors.append("The window has to close after it opens.")
    elif we <= now:
        errors.append("That window has already closed.")
    if not (target["hosts"] or target["groups"] or target["tags"]):
        errors.append("Choose at least one host, group or tag.")
    if errors:
        hosts = await db.fetch("SELECT id, name FROM hosts WHERE id = ANY(%s) ORDER BY name", host_ids)
        form["kinds"] = as_list(form.get("kinds"))
        return await _book_render(request, hosts, pins, form, errors, 400)
    title = str(form.get("title", "")).strip() or \
        f"{fleet.describe_selection(selection)} on {await fleet.describe_target(target)}"
    needs = form.get("needs_approval") == "1"
    bid = await db.fetchval(
        """INSERT INTO bookings (title, target, selection, window_start, window_end, on_window_close, batch_size,
                                 reboot, needs_approval, status, created_by)
           VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s) RETURNING id""",
        title[:200], J(target), J(selection), ws, we,
        form.get("on_window_close") if form.get("on_window_close") in fleet.WINDOW_CLOSE else "finish_started",
        _int(form.get("batch_size"), 1, 0, 100000),
        form.get("reboot") if form.get("reboot") in fleet.REBOOT_CHOICES else "if_needed",
        needs, "needs_approval" if needs else "booked", u["name"])
    request.session.pop("book_pins", None)
    await db.audit(u["name"], f"Booked install #{bid} '{title}' for {ws:%d %b %H:%M}–{we:%H:%M} UTC")
    flash(request, f"Booked for {ws:%a %d %b %H:%M}–{we:%H:%M} UTC."
          + (" It needs an admin's approval before then." if needs else ""))
    return redirect("/schedules#bookings")


@router.post("/schedules/bookings/{bid}/action")
async def booking_action(request: Request, bid: int):
    form = await form_data(request)
    action = form.get("action")
    b = await db.fetchone("SELECT * FROM bookings WHERE id = %s", bid)
    if not b:
        raise HTTPException(404)
    if action == "approve":
        u = require(request, "admin")
        await db.execute("UPDATE bookings SET approved_by = %s, status = 'booked' WHERE id = %s "
                         "AND status = 'needs_approval'", u["name"], bid)
        await db.audit(u["name"], f"Approved booked install #{bid} '{b['title']}'")
        flash(request, "Approved.")
    elif action == "cancel":
        u = require(request, "operator")
        await db.execute("UPDATE bookings SET status = 'cancelled' WHERE id = %s "
                         "AND status IN ('booked','needs_approval')", bid)
        await db.audit(u["name"], f"Cancelled booked install #{bid} '{b['title']}'")
        flash(request, "Cancelled.", "info")
    return redirect("/schedules#bookings")
