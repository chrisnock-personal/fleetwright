"""Hosts: the list, adding SSH hosts, a host's page and its actions."""

from __future__ import annotations

import fnmatch
import math
import re
from urllib.parse import urlencode

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import HTMLResponse

from .. import db, fleet
from ..webcommon import as_list, flash, form_data, redirect, render, require, split_words

router = APIRouter()

STATUS_FILTERS = {
    "all": ("All", "TRUE"),
    "updates": ("Needs updates", "h.pending_count > 0"),
    "security": ("Security", "h.security_count > 0"),
    "reboot": ("Reboot", "h.reboot_required"),
    "unreachable": ("Unreachable", "((h.mode = 'agent' AND NOT h.agent_connected) "
                                   "OR (h.mode = 'ssh' AND h.last_error LIKE 'Can''t connect%%'))"),
    "never": ("Not scanned", "h.last_scan_at IS NULL"),
}
NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,119}$")
PER_PAGE = (25, 50, 100, 250)


async def _choices() -> dict:
    return {
        "groups": await db.fetch("SELECT id, name FROM groups ORDER BY name"),
        "keys": await db.fetch("SELECT id, name, username FROM ssh_credentials ORDER BY name"),
        "oses": await db.fetch("SELECT DISTINCT os_pretty FROM hosts WHERE os_pretty IS NOT NULL ORDER BY 1"),
        "tags": await db.fetch("SELECT DISTINCT unnest(tags) AS tag FROM hosts ORDER BY 1"),
    }


@router.get("/hosts", response_class=HTMLResponse)
async def host_list(request: Request, status: str = "all", group: str = "", os: str = "", mode: str = "",
                    tag: str = "", q: str = "", page: int = 1, per: int = 25):
    status = status if status in STATUS_FILTERS else "all"
    per = per if per in PER_PAGE else 25
    where, args = ["TRUE"], []
    if group == "none":
        where.append("h.group_id IS NULL")
    elif group.isdigit():
        where.append("h.group_id = %s")
        args.append(int(group))
    if os:
        where.append("h.os_pretty = %s")
        args.append(os)
    if mode in ("ssh", "agent"):
        where.append("h.mode = %s")
        args.append(mode)
    if tag:
        where.append("%s = ANY(h.tags)")
        args.append(tag)
    if q:
        where.append("(h.name ILIKE %s OR h.address ILIKE %s OR EXISTS (SELECT 1 FROM pending_updates p "
                     "WHERE p.host_id = h.id AND (p.name ILIKE %s OR p.advisory ILIKE %s)))")
        like = f"%{q}%"
        args += [like, like, like, like]
    base = " AND ".join(where)
    counts = await db.fetchone(
        "SELECT " + ", ".join(f"COUNT(*) FILTER (WHERE {sql}) AS {k}" for k, (_, sql) in STATUS_FILTERS.items())
        + f" FROM hosts h WHERE {base}", *args)
    total = counts[status]
    pages = max(1, math.ceil(total / per))
    page = min(max(1, page), pages)
    rows = await db.fetch(
        f"""SELECT h.*, g.name AS group_name FROM hosts h LEFT JOIN groups g ON g.id = h.group_id
             WHERE {base} AND {STATUS_FILTERS[status][1]}
             ORDER BY h.security_count DESC, h.pending_count DESC, h.name
             LIMIT %s OFFSET %s""", *args, per, (page - 1) * per)
    return render(request, "hosts.html", hosts=rows, counts=counts, filters=STATUS_FILTERS, status=status,
                  f={"group": group, "os": os, "mode": mode, "tag": tag, "q": q}, page=page, pages=pages,
                  per=per, per_choices=PER_PAGE, total=total, **await _choices())


@router.post("/hosts/bulk")
async def host_bulk(request: Request):
    form = await form_data(request)
    u = require(request, "operator")
    ids = [int(i) for i in as_list(form.get("host")) if i.isdigit()]
    action = form.get("action")
    back = form.get("back") or "/hosts"
    if not ids:
        flash(request, "Tick at least one host first.", "bad")
        return redirect(back)
    if action == "schedule":
        return redirect("/schedules/book?" + urlencode([("host", i) for i in ids]))
    if action == "scan":
        n = await fleet.queue_scan(ids)
        flash(request, f"Scanning {n} host{'s' if n != 1 else ''}.")
        return redirect(back)
    if action in ("apply_security", "apply_all", "reboot"):
        selection = {"mode": "kinds", "kinds": ["security"]} if action == "apply_security" else {"mode": "all"}
        title = {"apply_security": "Security updates", "apply_all": "All updates", "reboot": "Reboot"}[action]
        run_id = await fleet.create_run(kind="reboot" if action == "reboot" else "apply", title=title,
                                        actor=u["name"], host_ids=ids, selection=selection,
                                        batch_size=int(form.get("batch") or 0) if str(form.get("batch") or "").isdigit() else 0,
                                        reboot="never")
        return redirect(f"/runs/{run_id}")
    if action == "tag":
        tags = split_words(form.get("tags"))
        if tags:
            await db.execute("""UPDATE hosts SET tags = ARRAY(SELECT DISTINCT unnest(tags || %s::text[]))
                                 WHERE id = ANY(%s)""", tags, ids)
            await db.audit(u["name"], f"Tagged {len(ids)} hosts: {', '.join(tags)}")
            flash(request, f"Tagged {len(ids)} hosts.")
        return redirect(back)
    if action == "group":
        gid = form.get("group_id")
        await db.execute("UPDATE hosts SET group_id = %s WHERE id = ANY(%s)",
                         int(gid) if str(gid).isdigit() else None, ids)
        flash(request, f"Moved {len(ids)} hosts.")
        return redirect(back)
    if action == "delete":
        require(request, "admin")
        names = [r["name"] for r in await db.fetch("SELECT name FROM hosts WHERE id = ANY(%s)", ids)]
        await db.execute("DELETE FROM hosts WHERE id = ANY(%s)", ids)
        await db.audit(u["name"], f"Removed {len(names)} hosts: {', '.join(names[:20])}")
        flash(request, f"Removed {len(names)} hosts. Agents on them stop being able to connect.")
        return redirect(back)
    raise HTTPException(400, "Unknown action")


@router.post("/hosts/scan-all")
async def scan_all(request: Request):
    await form_data(request)
    u = require(request, "operator")
    ids = [r["id"] for r in await db.fetch("SELECT id FROM hosts")]
    n = await fleet.queue_scan(ids)
    await db.audit(u["name"], f"Scanned all hosts ({n})")
    flash(request, f"Scanning {n} host{'s' if n != 1 else ''}. Results arrive over the next few minutes.")
    return redirect("/")


# ─── Adding SSH hosts ───────────────────────────────────────────────────────

@router.get("/hosts/new", response_class=HTMLResponse)
async def host_new_page(request: Request):
    require(request, "operator")
    return render(request, "host_new.html", form={}, errors=[], **await _choices())


def parse_host_lines(text: str) -> tuple[list[dict], list[str]]:
    """'name address[:port]' or just 'address' per line."""
    out, errors = [], []
    for n, raw in enumerate(text.splitlines(), 1):
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        parts = line.split()
        if len(parts) == 1:
            addr = parts[0]
            name = addr.split(":")[0]
        elif len(parts) == 2:
            name, addr = parts
        else:
            errors.append(f"Line {n}: expected 'name address' or 'address'")
            continue
        port = 22
        if addr.count(":") == 1:
            addr, p = addr.split(":")
            if not p.isdigit() or not 0 < int(p) < 65536:
                errors.append(f"Line {n}: bad port {p}")
                continue
            port = int(p)
        if not NAME_RE.match(name):
            errors.append(f"Line {n}: '{name}' isn't a usable host name")
            continue
        out.append({"name": name, "address": addr, "port": port})
    return out, errors


@router.post("/hosts/new")
async def host_new(request: Request):
    form = await form_data(request)
    u = require(request, "operator")
    found, errors = parse_host_lines(str(form.get("hosts", "")))
    if not found and not errors:
        errors.append("Enter at least one host.")
    if not str(form.get("credential_id", "")).isdigit():
        errors.append("Choose the SSH key to connect with (add one under Settings → SSH keys).")
    if errors:
        return render(request, "host_new.html", form=form, errors=errors, http_status=400, **await _choices())
    gid = int(form["group_id"]) if str(form.get("group_id", "")).isdigit() else None
    tags = split_words(form.get("tags"))
    added, existing = [], []
    for h in found:
        hid = await db.fetchval(
            """INSERT INTO hosts (name, address, port, mode, credential_id, group_id, tags)
               VALUES (%s, %s, %s, 'ssh', %s, %s, %s) ON CONFLICT (name) DO NOTHING RETURNING id""",
            h["name"], h["address"], h["port"], int(form["credential_id"]), gid, tags)
        (added if hid else existing).append(hid or h["name"])
    if added:
        await fleet.queue_scan(added)
        await db.audit(u["name"], f"Added {len(added)} SSH host{'s' if len(added) != 1 else ''}")
    msg = f"Added {len(added)} host{'s' if len(added) != 1 else ''}; scanning them now."
    if existing:
        msg += f" Already known, left alone: {', '.join(existing[:10])}."
    flash(request, msg, "ok" if added else "info")
    return redirect(f"/hosts/{added[0]}" if len(added) == 1 else "/hosts?status=all")


# ─── One host ───────────────────────────────────────────────────────────────

async def _host(host_id: int) -> dict:
    h = await db.fetchone("""SELECT h.*, g.name AS group_name, c.name AS key_name, c.username AS key_user
                               FROM hosts h LEFT JOIN groups g ON g.id = h.group_id
                               LEFT JOIN ssh_credentials c ON c.id = h.credential_id WHERE h.id = %s""", host_id)
    if not h:
        raise HTTPException(404, "No such host")
    return h


@router.get("/hosts/{host_id}", response_class=HTMLResponse)
async def host_page(request: Request, host_id: int, kind: str = "all"):
    h = await _host(host_id)
    pending = await db.fetch("""SELECT * FROM pending_updates WHERE host_id = %s AND current IS NOT NULL
                                ORDER BY is_security DESC,
                                         array_position(ARRAY['critical','important','moderate','low'], severity),
                                         is_kernel DESC, name""", host_id)
    held = set(h["held"] or [])
    for p in pending:
        p["held"] = any(fnmatch.fnmatchcase(p["name"], pat) for pat in held)
    counts = {"all": len(pending), "security": sum(p["is_security"] for p in pending),
              "kernel": sum(p["is_kernel"] for p in pending), "held": sum(p["held"] for p in pending)}
    shown = {"security": [p for p in pending if p["is_security"]], "kernel": [p for p in pending if p["is_kernel"]],
             "held": [p for p in pending if p["held"]]}.get(kind, pending)
    new_pkgs = await db.fetchval("SELECT COUNT(*) FROM pending_updates WHERE host_id = %s AND current IS NULL",
                                 host_id)
    history = await db.fetch("""SELECT t.*, r.title, r.id AS run_id FROM tasks t LEFT JOIN runs r ON r.id = t.run_id
                                 WHERE t.host_id = %s ORDER BY t.id DESC LIMIT 12""", host_id)
    changes = await db.fetch("""SELECT * FROM package_changes WHERE host_id = %s ORDER BY at DESC, name
                                 LIMIT 40""", host_id)
    active = await db.fetchone("""SELECT t.*, r.title FROM tasks t LEFT JOIN runs r ON r.id = t.run_id
                                   WHERE t.host_id = %s AND t.status IN ('queued','running')
                                   ORDER BY t.id LIMIT 1""", host_id)
    policies = await db.fetch("SELECT id, name, enabled, target FROM policies ORDER BY name")
    applies = [p for p in policies if host_id in await fleet.resolve_target(p["target"])] if policies else []
    return render(request, "host.html", h=h, pending=shown, counts=counts, kind=kind, new_pkgs=new_pkgs,
                  history=history, changes=changes, active_task=active, policies=applies, **await _choices())


@router.post("/hosts/{host_id}/action")
async def host_action(request: Request, host_id: int):
    form = await form_data(request)
    u = require(request, "operator")
    h = await _host(host_id)
    action = form.get("action")
    if action == "scan":
        await fleet.queue_scan([host_id])
        flash(request, f"Scanning {h['name']}.")
        return redirect(f"/hosts/{host_id}")
    picked = [p for p in as_list(form.get("pkg")) if "|" in p]
    if action in ("apply_selected", "schedule_selected"):
        if not picked:
            flash(request, "Tick the updates to install first.", "bad")
            return redirect(f"/hosts/{host_id}")
        rows = {(r["name"], r["arch"]): r for r in await db.fetch(
            "SELECT name, arch, available FROM pending_updates WHERE host_id = %s", host_id)}
        pkgs = []
        for p in picked:
            name, arch = p.split("|", 1)
            if (name, arch) in rows:
                pkgs.append({"name": name, "arch": arch, "version": rows[(name, arch)]["available"]})
        if action == "schedule_selected":
            request.session["book_pins"] = {str(host_id): pkgs}
            return redirect(f"/schedules/book?host={host_id}&pinned=1")
        run_id = await fleet.create_run(kind="apply", title=f"{len(pkgs)} picked updates", actor=u["name"],
                                        host_ids=[host_id], reboot=form.get("reboot") or "never",
                                        selection={"mode": "packages", "packages": {str(host_id): pkgs}})
        return redirect(f"/runs/{run_id}")
    if action in ("apply_security", "apply_all"):
        sel = {"mode": "kinds", "kinds": ["security"]} if action == "apply_security" else {"mode": "all"}
        run_id = await fleet.create_run(kind="apply", title="Security updates" if action == "apply_security"
                                        else "All updates", actor=u["name"], host_ids=[host_id], selection=sel,
                                        reboot=form.get("reboot") or "never")
        return redirect(f"/runs/{run_id}")
    if action == "reboot":
        run_id = await fleet.create_run(kind="reboot", title="Reboot", actor=u["name"], host_ids=[host_id])
        return redirect(f"/runs/{run_id}")
    raise HTTPException(400, "Unknown action")


@router.post("/hosts/{host_id}/edit")
async def host_edit(request: Request, host_id: int):
    form = await form_data(request)
    u = require(request, "operator")
    h = await _host(host_id)
    gid = int(form["group_id"]) if str(form.get("group_id", "")).isdigit() else None
    tags = split_words(form.get("tags"))
    held = split_words(form.get("held"))
    name = str(form.get("name", h["name"])).strip()
    if name != h["name"]:
        if not NAME_RE.match(name):
            flash(request, "Names use letters, digits, dots, dashes and underscores.", "bad")
            return redirect(f"/hosts/{host_id}")
        if await db.fetchval("SELECT EXISTS (SELECT 1 FROM hosts WHERE name = %s)", name):
            flash(request, f"Another host is already called {name}.", "bad")
            return redirect(f"/hosts/{host_id}")
        await db.execute("UPDATE hosts SET name = %s WHERE id = %s", name, host_id)
    if h["mode"] == "ssh":
        addr = str(form.get("address", h["address"])).strip()
        port = int(form["port"]) if str(form.get("port", "")).isdigit() else h["port"]
        cred = int(form["credential_id"]) if str(form.get("credential_id", "")).isdigit() else h["credential_id"]
        await db.execute("UPDATE hosts SET address = %s, port = %s, credential_id = %s WHERE id = %s",
                         addr, port, cred, host_id)
    await db.execute("UPDATE hosts SET group_id = %s, tags = %s, held = %s WHERE id = %s", gid, tags, held, host_id)
    await db.audit(u["name"], f"Edited host {h['name']}")
    flash(request, "Saved.")
    return redirect(f"/hosts/{host_id}")


@router.post("/hosts/{host_id}/forget-key")
async def host_forget_key(request: Request, host_id: int):
    await form_data(request)
    u = require(request, "admin")
    h = await _host(host_id)
    await db.execute("UPDATE hosts SET ssh_host_key = NULL, last_error = NULL WHERE id = %s", host_id)
    await db.audit(u["name"], f"Cleared the pinned SSH host key of {h['name']}")
    flash(request, "The pinned key is cleared; the next connection pins whatever key the host offers.", "info")
    return redirect(f"/hosts/{host_id}")


@router.post("/hosts/{host_id}/delete")
async def host_delete(request: Request, host_id: int):
    await form_data(request)
    u = require(request, "admin")
    h = await _host(host_id)
    await db.execute("DELETE FROM hosts WHERE id = %s", host_id)
    await db.audit(u["name"], f"Removed host {h['name']}")
    flash(request, f"Removed {h['name']}.")
    return redirect("/hosts")
