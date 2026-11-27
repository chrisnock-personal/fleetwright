"""Hosts: the list, adding SSH hosts, a host's page and its actions. Roles are checked by
the actions these call (actions/hosts.py, actions/runs.py), not here."""

from __future__ import annotations

import math
from urllib.parse import urlencode

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import HTMLResponse

from .. import db, gateway
from ..actions import hosts as host_actions
from ..actions import runs as run_actions
from ..actions.core import ActionError, invalid
from ..actions.hosts import STATUS_FILTERS, parse_host_lines  # noqa: F401 - tests import it from here
from ..webcommon import as_list, attempt, flash, form_data, redirect, render, require_action, split_words, who

router = APIRouter()
PER_PAGE = (25, 50, 100, 250)


async def _choices() -> dict:
    return {
        "groups": await db.fetch("SELECT id, name FROM groups ORDER BY name"),
        "keys": await db.fetch("SELECT id, name, username FROM ssh_credentials ORDER BY name"),
        "oses": await db.fetch("SELECT DISTINCT os_pretty FROM hosts WHERE os_pretty IS NOT NULL ORDER BY 1"),
        "tags": await db.fetch("SELECT DISTINCT unnest(tags) AS tag FROM hosts ORDER BY 1"),
    }


def _int(v) -> int | None:
    return int(v) if str(v or "").isdigit() else None


@router.get("/hosts", response_class=HTMLResponse)
async def host_list(request: Request, status: str = "all", group: str = "", os: str = "", mode: str = "",
                    tag: str = "", q: str = "", page: int = 1, per: int = 25):
    status = status if status in STATUS_FILTERS else "all"
    per = per if per in PER_PAGE else 25
    filters = dict(status=status, group=group, os=os, mode=mode, tag=tag, q=q, limit=per)
    page = max(1, page)
    r = await host_actions.list_hosts(who(request), **filters, offset=(page - 1) * per)
    pages = max(1, math.ceil(r["total"] / per))
    if page > pages:
        page = pages
        r = await host_actions.list_hosts(who(request), **filters, offset=(page - 1) * per)
    return render(request, "hosts.html", hosts=r["hosts"], counts=r["counts"], filters=STATUS_FILTERS,
                  status=status, f={"group": group, "os": os, "mode": mode, "tag": tag, "q": q}, page=page,
                  pages=pages, per=per, per_choices=PER_PAGE, total=r["total"], **await _choices())


async def _start(request: Request, back: str, **kw):
    r, bounce = await attempt(request, run_actions.start(who(request), **kw), back)
    return bounce or redirect(f"/runs/{r['run_id']}")


@router.post("/hosts/bulk")
async def host_bulk(request: Request):
    form = await form_data(request)
    p = who(request)
    ids = [int(i) for i in as_list(form.get("host")) if i.isdigit()]
    action = form.get("action")
    back = form.get("back") or "/hosts"
    if not ids:
        flash(request, "Tick at least one host first.", "bad")
        return redirect(back)
    target = {"hosts": ids}
    if action == "schedule":
        return redirect("/schedules/book?" + urlencode([("host", i) for i in ids]))
    if action == "scan":
        r = await host_actions.scan(p, ids)
        flash(request, f"Scanning {r['queued']} host{'s' if r['queued'] != 1 else ''}.")
        return redirect(back)
    if action in ("apply_security", "apply_all"):
        sel = {"mode": "kinds", "kinds": ["security"]} if action == "apply_security" else {"mode": "all"}
        return await _start(request, back, kind="apply", target=target, selection=sel,
                            title="Security updates" if action == "apply_security" else "All updates",
                            batch_size=_int(form.get("batch")) or 0)
    if action in ("reboot", "auto_off", "agent_update"):
        return await _start(request, back, kind=action, target=target)
    if action == "tag":
        tags = split_words(form.get("tags"))
        if tags:
            await host_actions.tag(p, ids, tags)
            flash(request, f"Tagged {len(ids)} hosts.")
        return redirect(back)
    if action == "group":
        await host_actions.move(p, ids, _int(form.get("group_id")))
        flash(request, f"Moved {len(ids)} hosts.")
        return redirect(back)
    if action == "delete":
        r = await host_actions.delete(p, ids)
        flash(request, f"Removed {len(r['removed'])} hosts. Agents on them stop being able to connect.")
        return redirect(back)
    raise HTTPException(400, "Unknown action")


@router.post("/hosts/scan-all")
async def scan_all(request: Request):
    await form_data(request)
    r = await host_actions.scan(who(request))
    n = r["queued"]
    flash(request, f"Scanning {n} host{'s' if n != 1 else ''}. Results arrive over the next few minutes.")
    return redirect("/")


# ─── Adding SSH hosts ───────────────────────────────────────────────────────

@router.get("/hosts/new", response_class=HTMLResponse)
async def host_new_page(request: Request):
    require_action(request, "hosts.add_ssh")
    return render(request, "host_new.html", form={}, errors=[], **await _choices())


@router.post("/hosts/new")
async def host_new(request: Request):
    form = await form_data(request)
    found, errors = parse_host_lines(str(form.get("hosts", "")))
    try:
        if errors:
            raise invalid(errors)
        r = await host_actions.add_ssh(who(request), found, _int(form.get("credential_id")),
                                       _int(form.get("group_id")), split_words(form.get("tags")),
                                       known_hosts=str(form.get("known_hosts") or ""))
    except ActionError as e:
        if e.code != "invalid":
            raise
        return render(request, "host_new.html", form=form, errors=e.errors, http_status=400, **await _choices())
    added, existing = r["added"], r["already_known"]
    msg = f"Added {len(added)} host{'s' if len(added) != 1 else ''}; scanning them now."
    if existing:
        msg += f" Already known, left alone: {', '.join(existing[:10])}."
    flash(request, msg, "ok" if added else "info")
    return redirect(f"/hosts/{added[0]}" if len(added) == 1 else "/hosts?status=all")


# ─── One host ───────────────────────────────────────────────────────────────

@router.get("/hosts/{host_id}", response_class=HTMLResponse)
async def host_page(request: Request, host_id: int, kind: str = "all"):
    p = who(request)
    h = await host_actions.get_host(p, host_id)
    pend = await host_actions.pending(p, host_id, kind)
    hist = await host_actions.history(p, host_id)
    history = await db.fetch("""SELECT t.*, r.title, r.id AS run_id FROM tasks t LEFT JOIN runs r ON r.id = t.run_id
                                 WHERE t.host_id = %s ORDER BY t.id DESC LIMIT 12""", host_id)
    return render(request, "host.html", h=h, server_agent=gateway.agent_bundle(), twins=h["same_machine_id"],
                  pending=pend["updates"], counts=pend["counts"], kind=kind, new_pkgs=pend["new_packages"],
                  history=history, changes=hist["changes"], active_task=h["active_task"], policies=h["policies"],
                  **await _choices())


@router.post("/hosts/{host_id}/action")
async def host_action(request: Request, host_id: int):
    form = await form_data(request)
    p = who(request)
    back = f"/hosts/{host_id}"
    action = form.get("action")
    target = {"hosts": [host_id]}
    reboot = form.get("reboot") or "never"
    if action == "scan":
        h = await host_actions.get_host(p, host_id)
        await host_actions.scan(p, [host_id])
        flash(request, f"Scanning {h['name']}.")
        return redirect(back)
    picked = [x.split("|", 1) for x in as_list(form.get("pkg")) if "|" in x]
    if action in ("apply_selected", "schedule_selected"):
        if not picked:
            flash(request, "Tick the updates to install first.", "bad")
            return redirect(back)
        chosen = {host_id: [{"name": n, "arch": a} for n, a in picked]}
        if action == "schedule_selected":
            require_action(request, "bookings.create")
            pins, bounce = await attempt(request, run_actions.pin_picked(chosen), back)
            if bounce:
                return bounce
            request.session["book_pins"] = pins
            return redirect(f"/schedules/book?host={host_id}&pinned=1")
        return await _start(request, back, kind="apply", target=target, picked=chosen, reboot=reboot)
    if action in ("apply_security", "apply_all"):
        sel = {"mode": "kinds", "kinds": ["security"]} if action == "apply_security" else {"mode": "all"}
        return await _start(request, back, kind="apply", target=target, selection=sel, reboot=reboot,
                            title="Security updates" if action == "apply_security" else "All updates")
    if action in ("reboot", "auto_off"):
        return await _start(request, back, kind=action, target=target)
    if action == "agent_update":
        return await _start(request, back, kind="agent_update", target=target, title="Update agent")
    raise HTTPException(400, "Unknown action")


@router.post("/hosts/{host_id}/edit")
async def host_edit(request: Request, host_id: int):
    form = await form_data(request)
    changes = {"name": str(form.get("name", "")).strip(), "group_id": _int(form.get("group_id")),
               "tags": split_words(form.get("tags")), "held": split_words(form.get("held"))}
    if not changes["name"]:
        del changes["name"]
    if "address" in form:
        changes["address"] = str(form.get("address", "")).strip()
    if _int(form.get("port")):
        changes["port"] = _int(form.get("port"))
    if _int(form.get("credential_id")):
        changes["credential_id"] = _int(form.get("credential_id"))
    _, bounce = await attempt(request, host_actions.edit(who(request), host_id, **changes), f"/hosts/{host_id}")
    if not bounce:
        flash(request, "Saved.")
    return bounce or redirect(f"/hosts/{host_id}")


@router.post("/hosts/{host_id}/forget-key")
async def host_forget_key(request: Request, host_id: int):
    await form_data(request)
    await host_actions.forget_key(who(request), host_id)
    flash(request, "The recorded host keys are cleared; the next connection pins whatever key the host offers.", "info")
    return redirect(f"/hosts/{host_id}")


@router.post("/hosts/{host_id}/known-hosts")
async def host_known_hosts(request: Request, host_id: int):
    """Replace the host keys recorded for one SSH host; an empty textarea clears them."""
    form = await form_data(request)
    _, bounce = await attempt(request,
                              host_actions.edit(who(request), host_id, known_hosts=str(form.get("known_hosts") or "")),
                              f"/hosts/{host_id}")
    if not bounce:
        flash(request, "Saved the host keys; every future connection checks them.", "ok")
    return bounce or redirect(f"/hosts/{host_id}")


@router.post("/hosts/{host_id}/delete")
async def host_delete(request: Request, host_id: int):
    await form_data(request)
    r = await host_actions.delete(who(request), [host_id])
    flash(request, f"Removed {r['removed'][0]}.")
    return redirect("/hosts")

