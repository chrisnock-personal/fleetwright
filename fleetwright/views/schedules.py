"""Schedules: auto-install policies, one-off booked installs and the week ahead. Roles are
checked by the actions these call (actions/schedules.py), not here."""

from __future__ import annotations

from datetime import datetime, time, timedelta, timezone
from typing import Optional

from fastapi import APIRouter, HTTPException, Query, Request
from fastapi.responses import HTMLResponse

from .. import db, fleet
from ..actions import schedules as sched
from ..actions.core import ActionError
from ..schedule import WEEKDAYS, next_run
from ..webcommon import as_list, attempt, flash, form_data, may, redirect, render, split_words, who

router = APIRouter()


def _week_strip(policies: list[dict], bookings: list[dict]) -> list[dict]:
    start = datetime.now(timezone.utc).replace(hour=0, minute=0, second=0, microsecond=0)
    days = [{"date": start + timedelta(days=i), "slots": []} for i in range(7)]
    end = start + timedelta(days=7)
    for p in policies:
        if not p["enabled"]:
            continue
        t = datetime.now(timezone.utc)   # what's still to come, not what already ran today
        at = p["at_time"] if isinstance(p["at_time"], time) else time.fromisoformat(p["at_time"])
        for _ in range(8):
            t = next_run(p["repeat"], at, t, p["weekdays"], p["monthday"])
            if t >= end:
                break
            days[(t - start).days]["slots"].append({"kind": "auto", "title": p["name"], "at": t,
                                                    "href": f"/schedules/policies/{p['id']}"})
    for b in bookings:
        if b["status"] in ("booked", "needs_approval", "started") and b["window_end"] > datetime.now(timezone.utc) \
                and start <= b["window_start"] < end:
            days[(b["window_start"] - start).days]["slots"].append(
                {"kind": "once", "title": b["title"], "at": b["window_start"], "until": b["window_end"],
                 "href": f"/runs/{b['run_id']}" if b["run_id"] else "#bookings"})
    for d in days:
        d["slots"].sort(key=lambda s: s["at"])
    return days


@router.get("/schedules", response_class=HTMLResponse)
async def schedules(request: Request):
    p = who(request)
    policies = (await sched.list_policies(p))["policies"]
    for pol in policies:
        pol["when_text"] = pol["schedule"]
    bookings = (await sched.list_bookings(p))["bookings"]
    return render(request, "schedules.html", policies=policies, bookings=bookings,
                  week=_week_strip(policies, bookings),
                  on_count=sum(1 for x in policies if x["enabled"]),
                  booked=sum(1 for b in bookings if b["status"] in ("booked", "needs_approval")))


# ─── Policies ───────────────────────────────────────────────────────────────

NEW_POLICY = {"id": None, "name": "", "enabled": False, "target": {"groups": [], "tags": [], "exclude_tags": []},
              "selection": {"mode": "kinds", "kinds": ["security"], "min_severity": "", "include": [], "exclude": []},
              "repeat": "daily", "weekdays": [6], "monthday": 1, "at_time": time(2, 0), "window_minutes": 120,
              "batch_size": 0, "batch_percent": 10, "canary": False, "max_failures": 2, "reboot": "if_needed"}


async def _policy_page(request: Request, p: dict, errors: Optional[list] = None, status: int = 200):
    groups = await db.fetch("SELECT id, name FROM groups ORDER BY name")
    tags = [r["tag"] for r in await db.fetch("SELECT DISTINCT unnest(tags) AS tag FROM hosts ORDER BY 1")]
    runs = await db.fetch("SELECT * FROM runs WHERE policy_id = %s ORDER BY id DESC LIMIT 8", p["id"]) \
        if p.get("id") else []
    try:
        pv = await sched.preview(who(request), p["target"], p["selection"])
    except ActionError:
        pv = {"hosts": 0, "updates": 0, "affected": 0, "reboot_hosts": 0}
    return render(request, "policy.html", p=p, groups=groups, tags=tags, weekdays=WEEKDAYS, errors=errors or [],
                  preview=pv, runs=runs, http_status=status, severities=fleet.SEVERITIES, kinds=fleet.KINDS)


@router.get("/schedules/policies/new", response_class=HTMLResponse)
async def policy_new(request: Request):
    may(request, "policies.save")
    return await _policy_page(request, dict(NEW_POLICY))


@router.get("/schedules/policies/{pid}", response_class=HTMLResponse)
async def policy_edit(request: Request, pid: int):
    await sched.get_policy(who(request), pid)   # the role check, and 404
    p = await db.fetchone("SELECT * FROM policies WHERE id = %s", pid)
    return await _policy_page(request, p)


def _int(value, default: int, lo: int, hi: int) -> int:
    try:
        return max(lo, min(hi, int(value)))
    except (TypeError, ValueError):
        return default


def policy_from_form(form: dict) -> dict:
    kinds = [k for k in as_list(form.get("kinds")) if k in fleet.KINDS]
    selection = {"mode": "all"} if form.get("what", "kinds") == "all" else {
        "mode": "kinds", "kinds": kinds, "min_severity": form.get("min_severity") or "",
        "include": split_words(form.get("include"))}
    selection["exclude"] = split_words(form.get("exclude"))
    batch_mode = form.get("batch_mode", "all")
    return {
        "name": str(form.get("name", "")).strip(), "enabled": form.get("enabled") == "1",
        "target": {"all": form.get("all_hosts") == "1",
                   "groups": [int(g) for g in as_list(form.get("groups")) if g.isdigit()],
                   "tags": split_words(form.get("tags")), "exclude_tags": split_words(form.get("exclude_tags"))},
        "selection": selection, "repeat": form.get("repeat") or "daily",
        "weekdays": [int(d) for d in as_list(form.get("weekdays")) if d.isdigit() and int(d) < 7],
        "monthday": _int(form.get("monthday"), 1, 1, 28), "at_time": str(form.get("at_time", "02:00")),
        "window_minutes": _int(form.get("window_minutes"), 120, 15, 24 * 60),
        "batch_size": _int(form.get("batch_size"), 10, 1, 100000) if batch_mode == "count" else 0,
        "batch_percent": _int(form.get("batch_percent"), 10, 1, 100) if batch_mode == "percent" else 0,
        "canary": form.get("canary") == "1", "max_failures": _int(form.get("max_failures"), 2, 0, 100000),
        "reboot": form.get("reboot") or "if_needed",
    }


@router.post("/schedules/policies/save")
async def policy_save(request: Request):
    form = await form_data(request)
    pid = int(form["id"]) if str(form.get("id", "")).isdigit() else None
    p = policy_from_form(form)
    try:
        r = await sched.save_policy(who(request), p, pid)
    except ActionError as e:
        if e.code != "invalid":
            raise
        shown = dict(p, id=pid)
        try:
            hh, mm = p["at_time"].split(":")[:2]
            shown["at_time"] = time(int(hh), int(mm))
        except ValueError:
            shown["at_time"] = time(2, 0)
        return await _policy_page(request, shown, e.errors, 400)
    nxt = r["next_run_at"]
    flash(request, f"Saved. {'Next run ' + nxt.strftime('%a %d %b %H:%M') + ' UTC.' if nxt else 'It is off.'}")
    return redirect(f"/schedules/policies/{r['policy_id']}")


@router.post("/schedules/policies/{pid}/action")
async def policy_action(request: Request, pid: int):
    form = await form_data(request)
    p = who(request)
    action = form.get("action")
    if action == "toggle":
        cur = await db.fetchone("SELECT enabled FROM policies WHERE id = %s", pid)
        if not cur:
            raise HTTPException(404, "No such policy")
        r = await sched.set_enabled(p, pid, not cur["enabled"])
        flash(request, f"{r['name']} is {'on' if r['enabled'] else 'off'}.")
        return redirect(form.get("back") or "/schedules")
    if action == "run_now":
        r = await sched.run_now(p, pid)
        return redirect(f"/runs/{r['run_id']}")
    if action == "delete":
        r = await sched.delete_policy(p, pid)
        flash(request, f"Deleted {r['deleted']}.")
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
    may(request, "bookings.create")
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
    pin_rows = [p for pkgs in (pins or {}).values() for p in pkgs]
    return render(request, "book.html", hosts=hosts, pins=pins, pin_rows=pin_rows, form=form, errors=errors,
                  groups=groups, kinds=fleet.KINDS, severities=fleet.SEVERITIES, http_status=status)


@router.post("/schedules/book")
async def book(request: Request):
    form = await form_data(request)
    host_ids = [int(h) for h in as_list(form.get("hosts")) if h.isdigit()]
    target = {"hosts": host_ids, "groups": [int(g) for g in as_list(form.get("groups")) if g.isdigit()],
              "tags": split_words(form.get("tags"))}
    pins = request.session.get("book_pins") if form.get("what") == "packages" else None
    picked = None
    if form.get("what") == "packages" and pins:
        # Already pinned when they were ticked; keep exactly those versions.
        picked_sel = {"mode": "packages", "packages": {k: v for k, v in pins.items() if int(k) in host_ids},
                      "exclude": split_words(form.get("exclude"))}
    else:
        picked_sel = None
    if form.get("what") == "all":
        selection = {"mode": "all"}
    else:
        selection = {"mode": "kinds", "kinds": [k for k in as_list(form.get("kinds")) if k in fleet.KINDS],
                     "min_severity": form.get("min_severity") or ""}
    selection["exclude"] = split_words(form.get("exclude"))
    try:
        r = await sched.book(who(request), target=target, selection=selection, picked=picked,
                             pinned=picked_sel,
                             window_start=_parse_local(str(form.get("window_start", ""))),
                             window_end=_parse_local(str(form.get("window_end", ""))),
                             title=str(form.get("title", "")),
                             on_window_close=form.get("on_window_close") or "finish_started",
                             batch_size=_int(form.get("batch_size"), 1, 0, 100000),
                             reboot=form.get("reboot") or "if_needed",
                             needs_approval=form.get("needs_approval") == "1")
    except ActionError as e:
        if e.code != "invalid":
            raise
        hosts = await db.fetch("SELECT id, name FROM hosts WHERE id = ANY(%s) ORDER BY name", host_ids)
        form["kinds"] = as_list(form.get("kinds"))
        form["groups"] = as_list(form.get("groups"))
        return await _book_render(request, hosts, pins, form, e.errors, 400)
    request.session.pop("book_pins", None)
    ws, we = r["window_start"], r["window_end"]
    flash(request, f"Booked for {ws:%a %d %b %H:%M}–{we:%H:%M} UTC."
          + (" It needs an admin's approval before then." if r["needs_approval"] else ""))
    return redirect("/schedules#bookings")


@router.post("/schedules/bookings/{bid}/action")
async def booking_action(request: Request, bid: int):
    form = await form_data(request)
    action = form.get("action")
    back = "/schedules#bookings"
    if action == "approve":
        _, bounce = await attempt(request, sched.approve(who(request), bid), back)
        if not bounce:
            flash(request, "Approved.")
    elif action == "cancel":
        _, bounce = await attempt(request, sched.cancel(who(request), bid), back)
        if not bounce:
            flash(request, "Cancelled.", "info")
    return redirect(back)
