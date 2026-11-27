"""Hosts: finding them, adding and editing them, and what's pending on them."""

from __future__ import annotations

import base64
import fnmatch
import re
from datetime import datetime
from typing import Optional

import asyncssh

from .. import db, fleet, gateway
from .core import Principal, action, invalid, not_found

STATUS_FILTERS = {
    "all": ("All", "TRUE"),
    "updates": ("Needs updates", "h.pending_count > 0"),
    "security": ("Security", "h.security_count > 0"),
    "reboot": ("Reboot", "h.reboot_required"),
    "unreachable": ("Unreachable", "((h.mode = 'agent' AND NOT h.agent_connected) "
                                   "OR (h.mode = 'ssh' AND h.last_error LIKE 'Can''t connect%%'))"),
    "never": ("Not scanned", "h.last_scan_at IS NULL"),
    "auto": ("Auto-updating", fleet.AUTO_UPDATING_SQL),
    "agent_old": ("Agent outdated", gateway.outdated_sql()),
}
NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,119}$")
PRIVATE = ("agent_token_hash",)


def public(row: dict) -> dict:
    return {k: v for k, v in row.items() if k not in PRIVATE}


async def _get(host_id: int) -> dict:
    h = await db.fetchone("""SELECT h.*, g.name AS group_name, c.name AS key_name, c.username AS key_user
                               FROM hosts h LEFT JOIN groups g ON g.id = h.group_id
                               LEFT JOIN ssh_credentials c ON c.id = h.credential_id WHERE h.id = %s""", host_id)
    if not h:
        raise not_found("host")
    return public(h)


@action("hosts.list", "viewer")
async def list_hosts(who: Principal, *, status: str = "all", group: str = "", os: str = "", mode: str = "",
                     tag: str = "", q: str = "", limit: int = 25, offset: int = 0,
                     after_id: Optional[int] = None) -> dict:
    """Hosts matching the hosts page's filters, with the count for each status."""
    status = status if status in STATUS_FILTERS else "all"
    where, args = ["TRUE"], []
    if group == "none":
        where.append("h.group_id IS NULL")
    elif str(group).isdigit():
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
    if after_id is not None:     # the API's cursor: by id, so pages never shift under it
        rows = await db.fetch(
            f"""SELECT h.*, g.name AS group_name FROM hosts h LEFT JOIN groups g ON g.id = h.group_id
                 WHERE {base} AND {STATUS_FILTERS[status][1]} AND h.id > %s ORDER BY h.id LIMIT %s""",
            *args, after_id, limit)
    else:                        # the page's order: most in need first
        rows = await db.fetch(
            f"""SELECT h.*, g.name AS group_name FROM hosts h LEFT JOIN groups g ON g.id = h.group_id
                 WHERE {base} AND {STATUS_FILTERS[status][1]}
                 ORDER BY h.security_count DESC, h.pending_count DESC, h.name LIMIT %s OFFSET %s""",
            *args, limit, offset)
    return {"hosts": [public(r) for r in rows], "counts": counts, "total": counts[status]}


@action("hosts.get", "viewer")
async def get_host(who: Principal, host_id: int) -> dict:
    """One host: what it is, its counts, the policies that apply to it and hosts sharing its machine id."""
    h = await _get(host_id)
    policies = await db.fetch("SELECT id, name, enabled, target FROM policies ORDER BY name")
    h["policies"] = [{"id": p["id"], "name": p["name"], "enabled": p["enabled"]} for p in policies
                     if host_id in await fleet.resolve_target(p["target"])]
    h["same_machine_id"] = await db.fetch(
        "SELECT id, name FROM hosts WHERE machine_id = %s AND id <> %s ORDER BY name",
        h["machine_id"], host_id) if h["machine_id"] else []
    h["active_task"] = await db.fetchone("""SELECT t.id, t.op, t.status, t.detail, t.run_id, r.title
                                             FROM tasks t LEFT JOIN runs r ON r.id = t.run_id
                                            WHERE t.host_id = %s AND t.status IN ('queued','running')
                                            ORDER BY t.id LIMIT 1""", host_id)
    return h


@action("hosts.pending", "viewer")
async def pending(who: Principal, host_id: int, kind: str = "all") -> dict:
    """A host's pending updates (kind: all, security, kernel, held), most urgent first."""
    h = await _get(host_id)
    rows = await db.fetch("""SELECT * FROM pending_updates WHERE host_id = %s AND current IS NOT NULL
                              ORDER BY is_security DESC,
                                       array_position(ARRAY['critical','important','moderate','low'], severity),
                                       is_kernel DESC, name""", host_id)
    held = set(h["held"] or [])
    for p in rows:
        p.pop("host_id", None)
        p["held"] = any(fnmatch.fnmatchcase(p["name"], pat) for pat in held)
    counts = {"all": len(rows), "security": sum(p["is_security"] for p in rows),
              "kernel": sum(p["is_kernel"] for p in rows), "held": sum(p["held"] for p in rows)}
    shown = {"security": [p for p in rows if p["is_security"]], "kernel": [p for p in rows if p["is_kernel"]],
             "held": [p for p in rows if p["held"]]}.get(kind, rows)
    new = await db.fetchval("SELECT COUNT(*) FROM pending_updates WHERE host_id = %s AND current IS NULL", host_id)
    return {"updates": shown, "counts": counts, "new_packages": new}


@action("hosts.history", "viewer")
async def history(who: Principal, host_id: int, *, since: Optional[datetime] = None, limit: int = 40,
                  before_id: Optional[int] = None) -> dict:
    """What FleetWright did to a host: package version changes and its recent tasks."""
    await _get(host_id)
    changes = await db.fetch(
        """SELECT id, task_id, name, from_version, to_version, at FROM package_changes
            WHERE host_id = %s AND (%s::timestamptz IS NULL OR at >= %s) AND (%s::bigint IS NULL OR id < %s)
            ORDER BY id DESC LIMIT %s""", host_id, since, since, before_id, before_id, limit)
    tasks = await db.fetch("""SELECT t.id, t.op, t.status, t.detail, t.created_at, t.finished_at, t.run_id, r.title
                                FROM tasks t LEFT JOIN runs r ON r.id = t.run_id
                               WHERE t.host_id = %s ORDER BY t.id DESC LIMIT 12""", host_id)
    return {"changes": changes, "tasks": tasks}


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


KNOWN_HOST_TYPES = ("ssh-ed25519", "ssh-rsa")


def parse_known_hosts(text: str) -> tuple[list[tuple[str, str]], list[str]]:
    """Parse pasted ``ssh-keyscan`` output into (host pattern, public key) pairs.

    Keys are returned in canonical ``'ssh-ed25519 AAAA…'`` form, the same format
    sshrun.py can hand to asyncssh. Unknown lines are reported with a line number
    rather than silently trusted: this is opt-in protection against a first-use
    impostor, so a typo must not turn back into trust-on-first-use.
    """
    entries, errors = [], []
    for n, raw in enumerate(str(text or "").splitlines(), 1):
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        parts = line.split()
        if len(parts) < 3:
            errors.append(f"Known host keys, line {n}: expected 'host ssh-ed25519 AAAA…' or "
                          "'host ssh-rsa AAAA…'")
            continue
        pattern, key_type, encoded = parts[:3]
        if key_type not in KNOWN_HOST_TYPES:
            errors.append(f"Known host keys, line {n}: '{key_type}' isn't a supported key type "
                          f"(use {' or '.join(KNOWN_HOST_TYPES)})")
            continue
        try:
            blob = base64.b64decode(encoded, validate=True)
            if not blob:
                raise ValueError("empty key")
            key = f"{key_type} {base64.b64encode(blob).decode('ascii')}"
            asyncssh.import_public_key(key)          # also rejects well-formed base64 that isn't an SSH key
        except ValueError:
            errors.append(f"Known host keys, line {n}: {key_type} key isn't valid base64/SSH key data")
            continue
        entries.append((pattern, key))
    return entries, errors


def _keys_for_host(entries: list[tuple[str, str]], host: dict) -> list[str]:
    """keyscan output may name a host by name, address or '[address]:port'. Prefer
    keys for this host; if none of the patterns match, keep every pasted key (a
    single-host add often uses a DNS name we don't record as the host's name)."""
    addr = str(host.get("address") or "")
    port = int(host.get("port") or 22)
    names = {str(host.get("name") or ""), addr, f"[{addr}]:{port}", f"{addr}:{port}"}
    names.discard("")
    matched = [key for pattern, key in entries if pattern.lower() in names]
    return list(dict.fromkeys(matched or [key for _, key in entries]))


@action("hosts.add_ssh", "operator")
async def add_ssh(who: Principal, hosts: list[dict], credential_id: Optional[int], group_id: Optional[int] = None,
                  tags: Optional[list[str]] = None, known_hosts: Optional[str] = None) -> dict:
    """Add agentless hosts ({name, address, port}) that FleetWright reaches over SSH with a stored key;
    known_hosts is optional pasted ssh-keyscan output, verified on every later connection."""
    entries, errors = parse_known_hosts(known_hosts)
    if known_hosts and str(known_hosts).strip() and not entries and not errors:
        errors.append("Known host keys: paste at least one ssh-keyscan line.")
    for h in hosts:
        if not NAME_RE.match(str(h.get("name", ""))):
            errors.append(f"'{h.get('name')}' isn't a usable host name")
        if not h.get("address"):
            errors.append(f"{h.get('name')}: no address")
        if not 0 < int(h.get("port") or 22) < 65536:
            errors.append(f"{h.get('name')}: bad port")
    if not hosts and not errors:
        errors.append("Enter at least one host.")
    if not credential_id or not await db.fetchval("SELECT EXISTS (SELECT 1 FROM ssh_credentials WHERE id = %s)",
                                                  credential_id):
        errors.append("Choose the SSH key to connect with (add one under Settings → SSH keys).")
    if errors:
        raise invalid(errors)
    added, existing = [], []
    for h in hosts:
        hid = await db.fetchval(
            """INSERT INTO hosts (name, address, port, mode, credential_id, group_id, tags, ssh_known_hosts)
               VALUES (%s, %s, %s, 'ssh', %s, %s, %s, %s) ON CONFLICT (name) DO NOTHING RETURNING id""",
            h["name"], h["address"], int(h.get("port") or 22), credential_id, group_id, list(tags or []),
            _keys_for_host(entries, h))
        (added if hid else existing).append(hid or h["name"])
    if added:
        await fleet.queue_scan(added)
        await db.audit(who.actor, f"Added {len(added)} SSH host{'s' if len(added) != 1 else ''}")
    return {"added": added, "already_known": existing}


_UNSET = object()


@action("hosts.edit", "operator")
async def edit(who: Principal, host_id: int, *, name=_UNSET, address=_UNSET, port=_UNSET, credential_id=_UNSET,
               group_id=_UNSET, tags=_UNSET, held=_UNSET, known_hosts=_UNSET) -> dict:
    """Change a host's name, group, tags, "never install" list, and (SSH hosts) address,
    port, key and recorded host keys (empty known_hosts clears them)."""
    h = await _get(host_id)
    keys = None
    if known_hosts is not _UNSET and h["mode"] == "ssh":
        entries, key_errors = parse_known_hosts(known_hosts)
        if key_errors:
            raise invalid(key_errors)
        keys = list(dict.fromkeys(key for _, key in entries))
    if name is not _UNSET and name != h["name"]:
        if not NAME_RE.match(str(name)):
            raise invalid("Names use letters, digits, dots, dashes and underscores.")
        if await db.fetchval("SELECT EXISTS (SELECT 1 FROM hosts WHERE name = %s)", name):
            raise invalid(f"Another host is already called {name}.")
        await db.execute("UPDATE hosts SET name = %s WHERE id = %s", name, host_id)
    if h["mode"] == "ssh":
        await db.execute("UPDATE hosts SET address = %s, port = %s, credential_id = %s WHERE id = %s",
                         h["address"] if address is _UNSET else address,
                         h["port"] if port is _UNSET or port is None else int(port),
                         h["credential_id"] if credential_id is _UNSET else credential_id, host_id)
        if keys is not None:
            # Supplied keys replace both the pasted set and any key pinned by first use.
            await db.execute("UPDATE hosts SET ssh_known_hosts = %s, ssh_host_key = NULL WHERE id = %s",
                             keys, host_id)
    await db.execute("UPDATE hosts SET group_id = %s, tags = %s, held = %s WHERE id = %s",
                     h["group_id"] if group_id is _UNSET else group_id,
                     h["tags"] if tags is _UNSET else list(tags or []),
                     h["held"] if held is _UNSET else list(held or []), host_id)
    await db.audit(who.actor, f"Edited host {h['name']}")
    return await _get(host_id)


@action("hosts.tag", "operator")
async def tag(who: Principal, host_ids: list[int], tags: list[str]) -> dict:
    """Add tags to hosts."""
    if tags:
        await db.execute("""UPDATE hosts SET tags = ARRAY(SELECT DISTINCT unnest(tags || %s::text[]))
                             WHERE id = ANY(%s)""", tags, host_ids)
        await db.audit(who.actor, f"Tagged {len(host_ids)} hosts: {', '.join(tags)}")
    return {"hosts": len(host_ids)}


@action("hosts.move", "operator")
async def move(who: Principal, host_ids: list[int], group_id: Optional[int]) -> dict:
    """Move hosts to a group (or out of any)."""
    await db.execute("UPDATE hosts SET group_id = %s WHERE id = ANY(%s)", group_id, host_ids)
    await db.audit(who.actor, f"Moved {len(host_ids)} hosts to group #{group_id}" if group_id
                   else f"Took {len(host_ids)} hosts out of their groups")
    return {"hosts": len(host_ids)}


@action("hosts.scan", "operator")
async def scan(who: Principal, host_ids: Optional[list[int]] = None) -> dict:
    """Scan hosts for updates now (all hosts when none are given)."""
    every = host_ids is None
    ids = [r["id"] for r in await db.fetch("SELECT id FROM hosts")] if every else host_ids
    n = await fleet.queue_scan(ids)
    if every:
        await db.audit(who.actor, f"Scanned all hosts ({n})")
    return {"queued": n}


@action("hosts.forget_key", "admin")
async def forget_key(who: Principal, host_id: int) -> dict:
    """Clear a host's pinned and pasted SSH host keys; the next connection pins whatever key it offers."""
    h = await _get(host_id)
    await db.execute("UPDATE hosts SET ssh_host_key = NULL, ssh_known_hosts = '{}', last_error = NULL WHERE id = %s",
                     host_id)
    await db.audit(who.actor, f"Cleared the SSH host keys of {h['name']}")
    return {"ok": True}


@action("hosts.delete", "admin")
async def delete(who: Principal, host_ids: list[int]) -> dict:
    """Remove hosts and their history. Agents on them can no longer connect."""
    names = [r["name"] for r in await db.fetch("SELECT name FROM hosts WHERE id = ANY(%s)", host_ids)]
    if not names:
        raise not_found("host")
    await db.execute("DELETE FROM hosts WHERE id = ANY(%s)", host_ids)
    await db.audit(who.actor, f"Removed host {names[0]}" if len(names) == 1
                   else f"Removed {len(names)} hosts: {', '.join(names[:20])}")
    return {"removed": names}
