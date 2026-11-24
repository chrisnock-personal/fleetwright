"""Auto-install policies and booked installs."""

from __future__ import annotations

from datetime import datetime, time, timezone
from typing import Optional

from psycopg import sql

from .. import db, fleet, notify, pkgops
from ..db import J
from ..schedule import describe, next_run
from .core import ActionError, Principal, action, invalid, not_found
from .runs import check_selection

# ─── What a policy would install ────────────────────────────────────────────

# A glob (as pkgops matches with fnmatch: *, ?, [seq], [!seq]) as an anchored Postgres regex.
GLOB_RE = (r"""'^' || replace(replace(replace(regexp_replace({0}, '([.+^$(){{}}|\\])', '\\\1', 'g'),
               '*', '.*'), '?', '.'), '[!', '[^') || '$'""")


def selection_sql(selection: dict) -> tuple[str, list]:
    """The WHERE clause that picks, from pending_updates p joined to h (with h.held_re,
    the host's held globs as regexes), what pkgops.select would pick for an "all" or
    "kinds" selection. Used to count; installs still go through pkgops.select."""
    def any_of(param: str) -> str:
        # Converted once per query (an uncorrelated subquery), not once per row.
        return f"p.name ~ ANY(ARRAY(SELECT {GLOB_RE.format('g')} FROM unnest({param}) g))"

    where = ["p.current IS NOT NULL", "(cardinality(h.held_re) = 0 OR NOT p.name ~ ANY(h.held_re))"]
    args: list = []
    if selection.get("exclude"):
        where.append("NOT " + any_of("%s::text[]"))
        args.append(list(selection["exclude"]))
    if selection.get("mode", "all") != "all":
        sev = "COALESCE(array_position(ARRAY['low','moderate','important','critical'], p.severity), 0)"
        min_sev = pkgops.SEVERITY_ORDER.get((selection.get("min_severity") or "").lower(), 0)
        kinds = set(selection.get("kinds") or [])
        take = ["FALSE"]
        if selection.get("include"):
            take.append(any_of("%s::text[]"))
            args.append(list(selection["include"]))
        if "security" in kinds:
            take.append(f"(p.is_security AND ({sev} = 0 OR {sev} >= {int(min_sev)}))")
        if "kernel" in kinds:
            take.append("p.is_kernel")
        if "bugfix" in kinds:
            take.append("(p.kind = 'bugfix' AND NOT p.is_security)")
        if "enhancement" in kinds:
            take.append("p.kind = 'enhancement'")
        where.append("(" + " OR ".join(take) + ")")
    return " AND ".join(where), args


async def _preview_python(host_ids: list[int], selection: dict) -> tuple[int, int, int]:
    rows = await db.fetch("""SELECT p.*, h.held FROM pending_updates p JOIN hosts h ON h.id = p.host_id
                              WHERE p.host_id = ANY(%s)""", host_ids)
    by_host: dict[int, list] = {}
    for r in rows:
        by_host.setdefault(r["host_id"], []).append(r)
    updates = affected = kernel_hosts = 0
    for pend in by_host.values():
        chosen, _ = pkgops.select(pend, selection, pend[0]["held"] or [])
        if chosen:
            affected += 1
            updates += len(chosen)
            kernel_hosts += any(p["is_kernel"] for p in chosen)
    return updates, affected, kernel_hosts


async def compute_preview(target: dict, selection: dict) -> dict:
    """How many updates a target and selection would install right now, from the last scans."""
    host_ids = await fleet.resolve_target(target)
    if not host_ids:
        return {"hosts": 0, "updates": 0, "affected": 0, "reboot_hosts": 0}
    if selection.get("mode") == "packages":
        updates, affected, kernel_hosts = await _preview_python(host_ids, selection)
    else:
        where, args = selection_sql(selection)
        row = await db.fetchone(
            f"""WITH h AS (SELECT id, ARRAY(SELECT {GLOB_RE.format('g')} FROM unnest(held) g) AS held_re
                           FROM hosts WHERE id = ANY(%s))
                SELECT COUNT(*) AS updates, COUNT(DISTINCT p.host_id) AS affected,
                       COUNT(DISTINCT p.host_id) FILTER (WHERE p.is_kernel) AS kernel_hosts
                  FROM pending_updates p JOIN h ON h.id = p.host_id
                 WHERE {where}""", host_ids, *args)
        updates, affected, kernel_hosts = row["updates"], row["affected"], row["kernel_hosts"]
    already = await db.fetchval("SELECT COUNT(*) FROM hosts WHERE id = ANY(%s) AND reboot_required", host_ids)
    return {"hosts": len(host_ids), "updates": updates, "affected": affected, "reboot_hosts": kernel_hosts + already}


@action("policies.preview", "viewer")
async def preview(who: Principal, target: dict, selection: dict) -> dict:
    """What a policy with this target and selection would install if it ran now: hosts matched,
    updates, hosts affected, hosts that would likely need a reboot."""
    return await compute_preview(target, check_selection(selection))


# ─── Policies ───────────────────────────────────────────────────────────────

POLICY_FIELDS = ["name", "enabled", "target", "selection", "repeat", "weekdays", "monthday", "at_time",
                 "window_minutes", "batch_size", "batch_percent", "canary", "max_failures", "reboot"]


def _policy_out(p: dict) -> dict:
    p = dict(p)
    p["schedule"] = describe(p)
    p["at_time"] = p["at_time"].strftime("%H:%M") if isinstance(p["at_time"], time) else p["at_time"]
    return p


async def _policy(pid: int) -> dict:
    p = await db.fetchone("SELECT * FROM policies WHERE id = %s", pid)
    if not p:
        raise not_found("policy")
    return p


@action("policies.list", "viewer")
async def list_policies(who: Principal) -> dict:
    """Every auto-install policy, switched-on ones first."""
    rows = await db.fetch("SELECT * FROM policies ORDER BY enabled DESC, name")
    out = []
    for p in rows:
        p = _policy_out(p)
        p["target_text"] = await fleet.describe_target(p["target"])
        out.append(p)
    return {"policies": out}


@action("policies.get", "viewer")
async def get_policy(who: Principal, policy_id: int) -> dict:
    """One policy, with what it would install now and its recent runs."""
    p = await _policy(policy_id)
    out = _policy_out(p)
    out["preview"] = await compute_preview(p["target"], p["selection"])
    out["runs"] = await db.fetch("SELECT id, title, status, note, created_at, finished_at FROM runs "
                                 "WHERE policy_id = %s ORDER BY id DESC LIMIT 8", policy_id)
    return out


def check_policy(p: dict) -> dict:
    """Validates and normalises a policy as the form and the API give it; raises invalid with every problem."""
    errors = []
    p = dict(p)
    p["name"] = str(p.get("name") or "").strip()
    if not p["name"]:
        errors.append("Give the policy a name.")
    try:
        p["selection"] = check_selection(p.get("selection"))
        if p["selection"]["mode"] == "packages":
            errors.append("A policy installs by kind or everything, not picked versions.")
    except ActionError as e:
        errors += e.errors
    t = p.get("target") or {}
    p["target"] = {"all": bool(t.get("all")), "groups": [int(g) for g in t.get("groups") or []],
                   "tags": list(t.get("tags") or []), "exclude_tags": list(t.get("exclude_tags") or [])}
    if not (p["target"]["all"] or p["target"]["groups"] or p["target"]["tags"]):
        errors.append("Choose which hosts it applies to: all, some groups or some tags.")
    at = p.get("at_time", "02:00")
    if not isinstance(at, time):
        try:
            hh, mm = str(at).split(":")[:2]
            at = time(int(hh), int(mm))
        except ValueError:
            at = time(2, 0)
            errors.append("The start time should look like 02:00.")
    p["at_time"] = at
    p["repeat"] = p.get("repeat") or "daily"
    if p["repeat"] not in ("daily", "weekly", "monthly"):
        errors.append("repeat is daily, weekly or monthly.")
    p["weekdays"] = sorted({int(d) for d in p.get("weekdays") or [] if 0 <= int(d) < 7})
    if p["repeat"] == "weekly" and not p["weekdays"]:
        errors.append("Pick at least one day of the week.")
    p["monthday"] = max(1, min(28, int(p.get("monthday") or 1)))
    p["window_minutes"] = max(15, min(24 * 60, int(p.get("window_minutes") or 120)))
    p["batch_size"] = max(0, int(p.get("batch_size") or 0))
    p["batch_percent"] = max(0, min(100, int(p.get("batch_percent") or 0)))
    p["max_failures"] = max(0, int(p.get("max_failures") if p.get("max_failures") is not None else 2))
    p["canary"] = bool(p.get("canary"))
    p["enabled"] = bool(p.get("enabled"))
    p["reboot"] = p.get("reboot") or "if_needed"
    if p["reboot"] not in fleet.REBOOT_CHOICES:
        errors.append(f"reboot is one of {', '.join(fleet.REBOOT_CHOICES)}.")
    if errors:
        raise invalid(errors)
    return p


@action("policies.save", "operator")
async def save_policy(who: Principal, policy: dict, policy_id: Optional[int] = None) -> dict:
    """Create a policy, or replace one's settings: which updates, which hosts, when, in what batches."""
    p = check_policy(policy)
    if policy_id:
        await _policy(policy_id)
    nxt = next_run(p["repeat"], p["at_time"], datetime.now(timezone.utc), p["weekdays"], p["monthday"])
    vals = [J(p[c]) if c in ("target", "selection") else p[c] for c in POLICY_FIELDS]
    try:
        if policy_id:
            sets = sql.SQL(", ").join(sql.SQL("{} = %s").format(sql.Identifier(c)) for c in POLICY_FIELDS)
            await db.execute(sql.SQL("UPDATE policies SET {}, next_run_at = %s WHERE id = %s").format(sets),
                             *vals, nxt, policy_id)
        else:
            cols = sql.SQL(", ").join(sql.Identifier(c) for c in POLICY_FIELDS)
            marks = sql.SQL(", ").join(sql.Placeholder() for _ in POLICY_FIELDS)
            policy_id = await db.fetchval(
                sql.SQL("INSERT INTO policies ({}, next_run_at, created_by) VALUES ({}, %s, %s) RETURNING id")
                .format(cols, marks), *vals, nxt, who.actor)
    except Exception as e:
        if "unique" in str(e).lower():
            raise invalid("Another policy already has that name.") from e
        raise
    await db.audit(who.actor, f"Saved policy {p['name']} ({'on' if p['enabled'] else 'off'})")
    return {"policy_id": policy_id, "next_run_at": nxt if p["enabled"] else None}


@action("policies.set_enabled", "operator")
async def set_enabled(who: Principal, policy_id: int, enabled: bool) -> dict:
    """Switch a policy on or off."""
    p = await _policy(policy_id)
    nxt = next_run(p["repeat"], p["at_time"], datetime.now(timezone.utc), p["weekdays"], p["monthday"])
    await db.execute("UPDATE policies SET enabled = %s, next_run_at = %s WHERE id = %s", enabled, nxt, policy_id)
    await db.audit(who.actor, f"Turned policy {p['name']} {'on' if enabled else 'off'}")
    return {"enabled": enabled, "name": p["name"]}


@action("policies.run_now", "operator")
async def run_now(who: Principal, policy_id: int) -> dict:
    """Run a policy straight away, outside its window, with its own settings."""
    p = await _policy(policy_id)
    hosts = await fleet.resolve_target(p["target"])
    run_id = await fleet.create_run(
        kind="apply", title=f"{p['name']} (run by hand)", actor=who.actor, host_ids=hosts,
        selection=p["selection"], batch_size=p["batch_size"], batch_percent=p["batch_percent"],
        canary=p["canary"], max_failures=p["max_failures"], reboot=p["reboot"], policy_id=policy_id)
    return {"run_id": run_id}


@action("policies.delete", "operator")
async def delete_policy(who: Principal, policy_id: int) -> dict:
    """Delete a policy (its past runs stay)."""
    p = await _policy(policy_id)
    await db.execute("DELETE FROM policies WHERE id = %s", policy_id)
    await db.audit(who.actor, f"Deleted policy {p['name']}")
    return {"deleted": p["name"]}


# ─── Booked installs ────────────────────────────────────────────────────────

@action("bookings.list", "viewer")
async def list_bookings(who: Principal) -> dict:
    """Booked installs: upcoming ones first, then those of the last two weeks."""
    rows = await db.fetch("""SELECT * FROM bookings
                              WHERE status IN ('booked','needs_approval','started')
                                 OR window_end > NOW() - INTERVAL '14 days'
                              ORDER BY (status IN ('booked','needs_approval','started')) DESC,
                                       window_start DESC LIMIT 50""")
    for b in rows:
        b["target_text"] = await fleet.describe_target(b["target"])
    return {"bookings": rows}


@action("bookings.create", "operator")
async def book(who: Principal, *, target: dict, selection: Optional[dict] = None, picked: Optional[dict] = None,
               pinned: Optional[dict] = None, window_start: Optional[datetime], window_end: Optional[datetime], title: str = "",
               on_window_close: str = "finish_started", batch_size: int = 1, reboot: str = "if_needed",
               needs_approval: bool = False) -> dict:
    """Book a one-off install for a window: everything, by kind, or picked updates pinned to their versions
    (picked: names, pinned to what's pending now; pinned: a packages selection pinned earlier)."""
    from .runs import pin_picked
    errors = []
    target = {"hosts": [int(h) for h in target.get("hosts") or []],
              "groups": [int(g) for g in target.get("groups") or []], "tags": list(target.get("tags") or [])}
    if pinned:
        if pinned.get("mode") != "packages" or not isinstance(pinned.get("packages"), dict):
            errors.append("pinned is a packages selection")
        selection = pinned
    elif picked:
        try:
            selection = {"mode": "packages", "packages": await pin_picked(picked),
                         "exclude": list((selection or {}).get("exclude") or [])}
        except ActionError as e:
            errors += e.errors
    else:
        try:
            selection = check_selection(selection)
        except ActionError as e:
            errors += e.errors
    now = datetime.now(timezone.utc)
    if not window_start or not window_end:
        errors.append("Enter when the window opens and closes.")
    elif window_end <= window_start:
        errors.append("The window has to close after it opens.")
    elif window_end <= now:
        errors.append("That window has already closed.")
    if not (target["hosts"] or target["groups"] or target["tags"]):
        errors.append("Choose at least one host, group or tag.")
    if on_window_close not in fleet.WINDOW_CLOSE:
        errors.append(f"on_window_close is one of {', '.join(fleet.WINDOW_CLOSE)}")
    if reboot not in fleet.REBOOT_CHOICES:
        errors.append(f"reboot is one of {', '.join(fleet.REBOOT_CHOICES)}")
    if errors:
        raise invalid(errors)
    ws, we = window_start, window_end
    title = (title or "").strip() or \
        f"{fleet.describe_selection(selection)} on {await fleet.describe_target(target)}"
    bid = await db.fetchval(
        """INSERT INTO bookings (title, target, selection, window_start, window_end, on_window_close, batch_size,
                                 reboot, needs_approval, status, created_by)
           VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s) RETURNING id""",
        title[:200], J(target), J(selection), ws, we, on_window_close, max(0, min(100000, int(batch_size))),
        reboot, needs_approval, "needs_approval" if needs_approval else "booked", who.actor)
    await db.audit(who.actor, f"Booked install #{bid} '{title}' for {ws:%d %b %H:%M}–{we:%H:%M} UTC")
    if needs_approval:
        await notify.emit("approval", f"Booked install {title} needs approval",
                          f"{who.actor} booked it for {ws:%a %d %b %H:%M}–{we:%H:%M} UTC: "
                          f"{await fleet.describe_target(target)} · {fleet.describe_selection(selection)}. "
                          "An admin has to approve it before the window opens, or it won't run.",
                          notify.url("/schedules#bookings"))
    return {"booking_id": bid, "window_start": ws, "window_end": we, "needs_approval": needs_approval}


async def _booking(bid: int) -> dict:
    b = await db.fetchone("SELECT * FROM bookings WHERE id = %s", bid)
    if not b:
        raise not_found("booking")
    return b


@action("bookings.approve", "admin")
async def approve(who: Principal, booking_id: int) -> dict:
    """Approve a booked install that needs an admin's approval."""
    b = await _booking(booking_id)
    n = await db.execute("UPDATE bookings SET approved_by = %s, status = 'booked' WHERE id = %s "
                         "AND status = 'needs_approval'", who.actor, booking_id)
    if not n:
        raise invalid(f"Booking #{booking_id} is {b['status']}, not waiting for approval.")
    await db.audit(who.actor, f"Approved booked install #{booking_id} '{b['title']}'")
    return {"status": "booked"}


@action("bookings.cancel", "operator")
async def cancel(who: Principal, booking_id: int) -> dict:
    """Cancel a booked install that hasn't started."""
    b = await _booking(booking_id)
    n = await db.execute("UPDATE bookings SET status = 'cancelled' WHERE id = %s "
                         "AND status IN ('booked','needs_approval')", booking_id)
    if not n:
        raise invalid(f"Booking #{booking_id} is {b['status']}: only booked ones can be cancelled.")
    await db.audit(who.actor, f"Cancelled booked install #{booking_id} '{b['title']}'")
    return {"status": "cancelled"}
