"""The overview, and what admins look after: groups, SSH keys, enrolment tokens,
users, notifications, backups, HTTPS and the audit log."""

from __future__ import annotations

import asyncio
import json
import logging
import os
from datetime import datetime, timedelta, timezone
from typing import Optional

import asyncssh

from .. import config, db, fleet, gateway, notify, security, tls
from ..db import J
from .core import ROLES, Principal, action, invalid, not_found

log = logging.getLogger("fleetwright.actions")
SETUP_LINK_HOURS = 72
UNREACHABLE_SQL = ("((h.mode = 'agent' AND NOT h.agent_connected) "
                   "OR (h.mode = 'ssh' AND h.last_error LIKE 'Can''t connect%%'))")


# ─── Overview ───────────────────────────────────────────────────────────────

@action("overview.get", "viewer")
async def overview(who: Principal) -> dict:
    """The fleet at a glance: totals, groups, recent runs, hosts updated per day, OS mix and what needs attention."""
    totals, pkgs, runs24, groups, runs, days, oses, attention = await asyncio.gather(
        db.fetchone(f"""SELECT COUNT(*) AS hosts,
                COUNT(*) FILTER (WHERE pending_count > 0) AS with_updates,
                COUNT(*) FILTER (WHERE security_count > 0) AS with_security,
                COUNT(*) FILTER (WHERE reboot_required) AS reboot,
                COUNT(*) FILTER (WHERE {UNREACHABLE_SQL}) AS unreachable,
                COUNT(*) FILTER (WHERE {UNREACHABLE_SQL} AND mode = 'agent') AS unreachable_agent,
                COUNT(*) FILTER (WHERE mode = 'agent') AS agents,
                COUNT(*) FILTER (WHERE mode = 'ssh') AS ssh,
                COUNT(DISTINCT group_id) AS groups,
                MAX(last_scan_at) AS last_scan
              FROM hosts h"""),
        # hosts.pending_count is kept from each scan; counting pending_updates itself
        # meant reading every row (83 ms at 377k in the load test).
        db.fetchone("""SELECT (SELECT COALESCE(SUM(pending_count), 0) FROM hosts) AS pending,
                              (SELECT COUNT(DISTINCT advisory) FROM pending_updates WHERE is_security) AS advisories,
                              (SELECT COUNT(DISTINCT host_id) FROM pending_updates
                                WHERE severity = 'critical') AS critical_hosts"""),
        db.fetchone("""SELECT COUNT(*) AS runs, COUNT(*) FILTER (WHERE status = 'failed'
                              OR (status = 'done' AND note LIKE '%%failed')) AS failed,
                              COUNT(*) FILTER (WHERE status IN ('running', 'paused')) AS active
                         FROM runs WHERE created_at > NOW() - INTERVAL '24 hours' OR status IN ('running','paused')"""),
        db.fetch(f"""SELECT g.id, COALESCE(g.name, 'Ungrouped') AS name, COUNT(h.id) AS hosts,
                            COUNT(h.id) FILTER (WHERE h.pending_count = 0) AS ok,
                            COUNT(h.id) FILTER (WHERE h.pending_count > 0 AND h.security_count = 0) AS updates,
                            COUNT(h.id) FILTER (WHERE h.security_count > 0) AS security,
                            COUNT(h.id) FILTER (WHERE {UNREACHABLE_SQL}) AS unreachable,
                            COUNT(h.id) FILTER (WHERE h.reboot_required) AS reboot,
                            string_agg(DISTINCT initcap(h.os_id) || ' ' || h.os_version, ', ') AS oses,
                            string_agg(DISTINCT h.mode, ', ') AS modes
                       FROM hosts h LEFT JOIN groups g ON g.id = h.group_id
                      GROUP BY g.id, g.name ORDER BY g.name NULLS LAST"""),
        db.fetch("""SELECT r.*, COUNT(t.id) AS total,
                           COUNT(t.id) FILTER (WHERE t.status IN ('done','failed','skipped')) AS finished,
                           COUNT(t.id) FILTER (WHERE t.status = 'failed') AS failed
                      FROM runs r LEFT JOIN tasks t ON t.run_id = r.id
                     WHERE r.created_at > NOW() - INTERVAL '24 hours' OR r.status IN ('running','paused')
                     GROUP BY r.id ORDER BY (r.status IN ('running','paused')) DESC, r.id DESC LIMIT 6"""),
        db.fetch("""SELECT d::date AS day,
                           (SELECT COUNT(DISTINCT host_id) FROM package_changes
                             WHERE at >= d AND at < d + INTERVAL '1 day') AS hosts,
                           (SELECT COUNT(*) FROM tasks WHERE op = 'apply' AND status = 'failed'
                             AND finished_at >= d AND finished_at < d + INTERVAL '1 day') AS failed
                      FROM generate_series(date_trunc('day', NOW()) - INTERVAL '13 days',
                                           date_trunc('day', NOW()), INTERVAL '1 day') AS d"""),
        db.fetch("""SELECT COALESCE(os_pretty, 'Not scanned yet') AS name, COUNT(*) AS n
                      FROM hosts GROUP BY 1 ORDER BY n DESC LIMIT 6"""),
        db.fetch(f"""(SELECT h.id, h.name, 'Unreachable' AS badge, 'bad' AS tone,
                             COALESCE(h.last_error, 'Agent not connected') || ' · last seen ' AS detail,
                             h.last_seen AS at, 1 AS rank
                        FROM hosts h WHERE {UNREACHABLE_SQL} ORDER BY h.last_seen NULLS FIRST LIMIT 4)
                     UNION ALL
                     (SELECT h.id, h.name, 'Failed', 'bad', COALESCE(t.detail, 'failed') || ' · ', t.finished_at, 2
                        FROM tasks t JOIN hosts h ON h.id = t.host_id
                       WHERE t.status = 'failed' AND t.finished_at > NOW() - INTERVAL '24 hours'
                         AND t.op <> 'scan' ORDER BY t.finished_at DESC LIMIT 4)
                     UNION ALL
                     (SELECT h.id, h.name, 'Critical', 'warn', 'Critical security update waiting · scanned ',
                             h.last_scan_at, 3
                        FROM hosts h WHERE EXISTS (SELECT 1 FROM pending_updates p WHERE p.host_id = h.id
                                                   AND p.severity = 'critical') LIMIT 3)
                     UNION ALL
                     (SELECT h.id, h.name, 'Reboot', 'info', 'Reboot needed · running ' || COALESCE(h.kernel, '?')
                             || ' · ', h.last_scan_at, 4
                        FROM hosts h WHERE h.reboot_required LIMIT 3)
                     UNION ALL
                     (SELECT h.id, h.name, 'Auto-updating', 'warn',
                             (SELECT string_agg(a->>'tool', ', ') FROM jsonb_array_elements(h.auto_updates) a
                               WHERE (a->>'installs')::boolean)
                             || ' installs updates outside FleetWright · scanned ', h.last_scan_at, 5
                        FROM hosts h WHERE {fleet.AUTO_UPDATING_SQL} LIMIT 3)
                     ORDER BY rank LIMIT 8"""),
    )
    return {"totals": totals, "packages": pkgs, "runs_24h": runs24, "groups": groups, "recent_runs": runs,
            "days": days, "oses": oses, "attention": attention}


@action("overview.audit", "admin")
async def audit_log(who: Principal, *, limit: int = 300, before_id: Optional[int] = None) -> dict:
    """The audit log, newest first: who changed what."""
    rows = await db.fetch("SELECT * FROM audit_log WHERE (%s::bigint IS NULL OR id < %s) ORDER BY id DESC LIMIT %s",
                          before_id, before_id, limit)
    return {"entries": rows}


# ─── Groups ─────────────────────────────────────────────────────────────────

@action("groups.list", "viewer")
async def list_groups(who: Principal) -> dict:
    """Host groups, with how many hosts each has."""
    rows = await db.fetch("""SELECT g.*, (SELECT COUNT(*) FROM hosts h WHERE h.group_id = g.id) AS hosts
                               FROM groups g ORDER BY name""")
    return {"groups": rows}


@action("groups.save", "admin")
async def save_group(who: Principal, name: str, description: str = "", group_id: Optional[int] = None) -> dict:
    """Add a group, or rename one."""
    name = (name or "").strip()
    if not name:
        raise invalid("Give the group a name.")
    if group_id:
        if not await db.execute("UPDATE groups SET name = %s, description = %s WHERE id = %s",
                                name, description or "", group_id):
            raise not_found("group")
        await db.audit(who.actor, f"Renamed group to {name}")
        return {"group_id": group_id}
    gid = await db.fetchval("INSERT INTO groups (name, description) VALUES (%s, %s) ON CONFLICT (name) DO NOTHING "
                            "RETURNING id", name, description or "")
    if not gid:
        raise invalid(f"There's already a group called {name}.")
    await db.audit(who.actor, f"Added group {name}")
    return {"group_id": gid}


@action("groups.delete", "admin")
async def delete_group(who: Principal, group_id: int) -> dict:
    """Delete a group; its hosts stay, ungrouped."""
    g = await db.fetchone("SELECT name FROM groups WHERE id = %s", group_id)
    if not g:
        raise not_found("group")
    await db.execute("DELETE FROM groups WHERE id = %s", group_id)
    await db.audit(who.actor, f"Deleted group {g['name']}")
    return {"deleted": g["name"]}


# ─── SSH keys ───────────────────────────────────────────────────────────────

@action("keys.list", "admin")
async def list_keys(who: Principal) -> dict:
    """Stored SSH keys (public halves only) and how many hosts use each."""
    rows = await db.fetch("""SELECT c.id, c.name, c.username, c.public_key, c.created_at,
                                    (SELECT COUNT(*) FROM hosts h WHERE h.credential_id = c.id) AS hosts
                               FROM ssh_credentials c ORDER BY name""")
    return {"keys": rows}


@action("keys.add", "admin")
async def add_key(who: Principal, name: str, username: str = "root", private_key: str = "") -> dict:
    """Store an SSH key for agentless hosts: paste a private key, or leave it out to generate an ed25519 one."""
    name, username, pasted = (name or "").strip(), (username or "").strip() or "root", (private_key or "").strip()
    if not name:
        raise invalid("Give the key a name.")
    try:
        key = asyncssh.import_private_key(pasted) if pasted else asyncssh.generate_private_key("ssh-ed25519")
    except (asyncssh.KeyImportError, ValueError) as e:
        raise invalid(f"That private key can't be read ({e}). Keys with a passphrase aren't supported.") from e
    public = key.export_public_key().decode().strip() + f" fleetwright-{name}"
    try:
        kid = await db.fetchval("""INSERT INTO ssh_credentials (name, username, private_key_enc, public_key)
                                   VALUES (%s, %s, %s, %s) RETURNING id""",
                                name, username, security.encrypt(key.export_private_key().decode()), public)
    except Exception as e:
        if "unique" in str(e).lower():
            raise invalid("A key with that name already exists.") from e
        raise
    await db.audit(who.actor, f"{'Added' if pasted else 'Generated'} SSH key {name} (user {username})")
    return {"key_id": kid, "public_key": public, "generated": not pasted}


@action("keys.delete", "admin")
async def delete_key(who: Principal, key_id: int) -> dict:
    """Delete a stored SSH key. Hosts that used it need another."""
    k = await db.fetchone("SELECT name FROM ssh_credentials WHERE id = %s", key_id)
    if not k:
        raise not_found("SSH key")
    await db.execute("DELETE FROM ssh_credentials WHERE id = %s", key_id)
    await db.audit(who.actor, f"Deleted SSH key {k['name']}")
    return {"deleted": k["name"]}


# ─── Agents and enrolment ───────────────────────────────────────────────────

@action("agents.status", "admin")
async def agents_status(who: Principal) -> dict:
    """Enrolled agents, the agent version this server hands out, and the enrolment tokens."""
    agents = await db.fetchone(f"""SELECT COUNT(*) AS enrolled, COUNT(*) FILTER (WHERE agent_connected) AS connected,
                                          COUNT(*) FILTER (WHERE {gateway.outdated_sql()}
                                                           AND agent_bundle IS NOT NULL) AS updatable,
                                          COUNT(*) FILTER (WHERE agent_bundle IS NULL) AS too_old
                                     FROM hosts h WHERE mode = 'agent'""")
    tokens = await db.fetch("""SELECT t.id, t.label, t.group_id, g.name AS group_name, t.tags, t.uses_left,
                                      t.expires_at, t.created_by, t.created_at
                                 FROM enroll_tokens t LEFT JOIN groups g ON g.id = t.group_id ORDER BY t.id DESC""")
    return {"agents": agents, "server_agent": gateway.agent_bundle(), "tokens": tokens,
            "public_url": config.PUBLIC_URL}


@action("enroll.create", "admin")
async def create_enroll_token(who: Principal, label: str = "", group_id: Optional[int] = None,
                              tags: Optional[list[str]] = None, uses: Optional[int] = None, days: int = 7) -> dict:
    """Create an enrolment token, returned once with the install command to run on each host."""
    token = security.new_token(24)
    label = (label or "").strip() or "enrolment token"
    tid = await db.fetchval(
        """INSERT INTO enroll_tokens (token_hash, label, group_id, tags, uses_left, expires_at, created_by)
           VALUES (%s, %s, %s, %s, %s, %s, %s) RETURNING id""",
        security.token_hash(token), label, group_id, list(tags or []), uses if uses and uses > 0 else None,
        datetime.now(timezone.utc) + timedelta(days=max(1, min(int(days or 7), 365))), who.actor)
    await db.audit(who.actor, f"Created enrolment token '{label}'")
    return {"token_id": tid, "label": label, "token": token, "install_command": gateway.install_command(token)}


@action("enroll.revoke", "admin")
async def revoke_enroll_token(who: Principal, token_id: int) -> dict:
    """Revoke an enrolment token. Agents already enrolled with it keep working."""
    await db.execute("UPDATE enroll_tokens SET expires_at = NOW() WHERE id = %s AND expires_at > NOW()", token_id)
    await db.audit(who.actor, f"Revoked enrolment token #{token_id}")
    return {"ok": True}


# ─── Users ──────────────────────────────────────────────────────────────────

async def _admins() -> int:
    return await db.fetchval("SELECT COUNT(*) FROM users WHERE role = 'admin'")


async def _user(uid: int) -> dict:
    u = await db.fetchone("SELECT * FROM users WHERE id = %s", uid)
    if not u:
        raise not_found("user")
    return u


def _setup_link(token: str) -> str:
    return f"{config.PUBLIC_URL}/welcome/{token}"


@action("users.list", "admin")
async def list_users(who: Principal) -> dict:
    """Everyone with an account, their role and last sign-in."""
    rows = await db.fetch("""SELECT id, email, name, role, last_login, setup_expires,
                                    password_hash IS NOT NULL AS active FROM users ORDER BY role, name""")
    return {"users": rows}


@action("users.add", "admin")
async def add_user(who: Principal, email: str, name: str, role: str) -> dict:
    """Add someone; returns a single-use setup link (valid 72 hours) for them to choose a password."""
    email, name = (email or "").strip().lower(), (name or "").strip()
    if "@" not in email or not name or role not in ROLES:
        raise invalid("Enter a name, an email and a role.")
    token = security.new_token()
    uid = await db.fetchval(
        """INSERT INTO users (email, name, role, setup_token, setup_expires) VALUES (%s,%s,%s,%s,%s)
           ON CONFLICT (email) DO NOTHING RETURNING id""",
        email, name, role, security.token_hash(token), datetime.now(timezone.utc) + timedelta(hours=SETUP_LINK_HOURS))
    if not uid:
        raise invalid("Someone already has that email.")
    await db.audit(who.actor, f"Added {name} ({role})")
    return {"user_id": uid, "name": name, "token": token, "setup_link": _setup_link(token)}


@action("users.set_role", "admin")
async def set_role(who: Principal, user_id: int, role: str) -> dict:
    """Change someone's role. There's always at least one admin."""
    if role not in ROLES:
        raise invalid(f"role is one of {', '.join(ROLES)}")
    target = await _user(user_id)
    if target["role"] == "admin" and role != "admin" and await _admins() <= 1:
        raise invalid("There must always be at least one admin.")
    await db.execute("UPDATE users SET role = %s WHERE id = %s", role, user_id)
    # A token can't keep more than its person now has.
    await db.execute("""UPDATE api_tokens SET role = %s WHERE user_id = %s
                         AND array_position(ARRAY['viewer','operator','admin'], role)
                           > array_position(ARRAY['viewer','operator','admin'], %s)""", role, user_id, role)
    await db.audit(who.actor, f"Made {target['name']} {ROLES[role]}")
    return {"role": role}


@action("users.setup_link", "admin")
async def setup_link(who: Principal, user_id: int) -> dict:
    """A new single-use setup link for someone (to set or reset their password)."""
    target = await _user(user_id)
    token = security.new_token()
    await db.execute("UPDATE users SET setup_token = %s, setup_expires = %s WHERE id = %s",
                     security.token_hash(token), datetime.now(timezone.utc) + timedelta(hours=SETUP_LINK_HOURS),
                     user_id)
    await db.audit(who.actor, f"Created a setup link for {target['name']}")
    return {"name": target["name"], "token": token, "setup_link": _setup_link(token)}


@action("users.delete", "admin")
async def delete_user(who: Principal, user_id: int) -> dict:
    """Remove someone's account (and their API tokens)."""
    target = await _user(user_id)
    if target["id"] == who.user_id:
        raise invalid("You can't remove your own account.")
    if target["role"] == "admin" and await _admins() <= 1:
        raise invalid("There must always be at least one admin.")
    await db.execute("DELETE FROM users WHERE id = %s", user_id)
    await db.audit(who.actor, f"Removed {target['name']}")
    return {"deleted": target["name"]}


# ─── Notifications ──────────────────────────────────────────────────────────

def _channel_out(c: dict) -> dict:
    c = {k: v for k, v in c.items() if k != "secret_enc"}
    return c


@action("notifications.list", "admin")
async def list_channels(who: Principal) -> dict:
    """Notification channels (secrets left out), the events they can choose from and the unreachable wait."""
    rows = await db.fetch("""SELECT c.*, c.secret_enc IS NOT NULL AS has_secret,
                                    (SELECT COUNT(*) FROM notify_outbox o WHERE o.channel_id = c.id
                                       AND o.sent_at IS NULL) AS queued
                               FROM notify_channels c ORDER BY name""")
    grace = await db.fetchval("SELECT value FROM settings WHERE key = 'notify_unreachable_min'")
    return {"channels": [_channel_out(c) for c in rows], "events": notify.EVENTS, "kinds": notify.KINDS,
            "unreachable_minutes": int(grace or notify.UNREACHABLE_GRACE_DEFAULT)}


def channel_config(kind: str, cfg: dict) -> dict:
    errors = []
    if kind == "email":
        cfg = {k: str(cfg.get(k) or "").strip() for k in ("host", "port", "security", "username", "from", "to")}
        if cfg["security"] not in ("starttls", "ssl", "none"):
            cfg["security"] = "starttls"
        if cfg["port"] and not cfg["port"].isdigit():
            errors.append("The SMTP port is a number.")
        if not cfg["host"] or not cfg["from"] or not cfg["to"]:
            errors.append("An email channel needs an SMTP server, a From address and a To address.")
    else:
        cfg = {"url": str(cfg.get("url") or "").strip()}
        if not cfg["url"].startswith(("https://", "http://")):
            errors.append("The URL must start with https:// (or http://).")
    if errors:
        raise invalid(errors)
    return cfg


@action("notifications.save", "admin")
async def save_channel(who: Principal, *, name: str, events: list[str], config: dict, kind: str = "",
                       secret: Optional[str] = None, clear_secret: bool = False,
                       channel_id: Optional[int] = None) -> dict:
    """Add a notification channel (email, webhook or ntfy), or change one. A blank secret keeps the stored one."""
    old = await db.fetchone("SELECT * FROM notify_channels WHERE id = %s", channel_id) if channel_id else None
    if channel_id and not old:
        raise not_found("channel")
    kind = old["kind"] if old else kind
    errors = []
    if kind not in notify.KINDS:
        raise invalid("Choose email, webhook or ntfy.")
    try:
        cfg = channel_config(kind, config or {})
    except Exception as e:  # ActionError
        errors += getattr(e, "errors", [str(e)])
        cfg = {}
    name = (name or "").strip()[:80]
    events = [e for e in events or [] if e in notify.EVENTS]
    if not name:
        errors.append("Give the channel a name.")
    if not events:
        errors.append("Tick at least one thing to be told about.")
    if errors:
        raise invalid(errors)
    secret_enc = security.encrypt(secret) if secret else (old["secret_enc"] if old and not clear_secret else None)
    try:
        if old:
            await db.execute("""UPDATE notify_channels SET name = %s, config = %s, secret_enc = %s, events = %s
                                 WHERE id = %s""", name, J(cfg), secret_enc, events, channel_id)
            await db.audit(who.actor, f"Changed notification channel '{name}'")
        else:
            channel_id = await db.fetchval(
                """INSERT INTO notify_channels (name, kind, config, secret_enc, events, created_by)
                   VALUES (%s, %s, %s, %s, %s, %s) RETURNING id""", name, kind, J(cfg), secret_enc, events, who.actor)
            await db.audit(who.actor, f"Added {kind} notification channel '{name}'")
    except Exception as e:  # noqa: BLE001
        if "unique" in str(e).lower():
            raise invalid(f"There's already a channel called {name}.") from e
        raise
    return {"channel_id": channel_id}


async def _channel(cid: int) -> dict:
    c = await db.fetchone("SELECT * FROM notify_channels WHERE id = %s", cid)
    if not c:
        raise not_found("channel")
    return c


@action("notifications.test", "admin")
async def test_channel(who: Principal, channel_id: int) -> dict:
    """Send a test message through a channel now; any error is returned and shown on the channel."""
    c = await _channel(channel_id)
    try:
        await notify.send_test(c)
    except Exception as e:  # noqa: BLE001 - reported
        await db.execute("UPDATE notify_channels SET last_error = %s WHERE id = %s", str(e)[:500], channel_id)
        return {"sent": False, "error": str(e)}
    await db.execute("UPDATE notify_channels SET last_sent_at = NOW(), last_error = NULL WHERE id = %s", channel_id)
    return {"sent": True}


@action("notifications.set_enabled", "admin")
async def set_channel_enabled(who: Principal, channel_id: int, enabled: bool) -> dict:
    """Turn a channel on or off."""
    c = await _channel(channel_id)
    await db.execute("UPDATE notify_channels SET enabled = %s WHERE id = %s", enabled, channel_id)
    await db.audit(who.actor, f"{'Enabled' if enabled else 'Disabled'} notification channel '{c['name']}'")
    return {"enabled": enabled}


@action("notifications.delete", "admin")
async def delete_channel(who: Principal, channel_id: int) -> dict:
    """Delete a notification channel."""
    c = await _channel(channel_id)
    await db.execute("DELETE FROM notify_channels WHERE id = %s", channel_id)
    await db.audit(who.actor, f"Deleted notification channel '{c['name']}'")
    return {"deleted": c["name"]}


@action("notifications.options", "admin")
async def notification_options(who: Principal, unreachable_minutes: int) -> dict:
    """How long a host must be unreachable before it's reported (1 to 10080 minutes)."""
    if not 1 <= int(unreachable_minutes) <= 10080:
        raise invalid("Give the wait in minutes, 1 to 10080.")
    await db.execute("""INSERT INTO settings (key, value) VALUES ('notify_unreachable_min', %s)
                        ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value""", str(int(unreachable_minutes)))
    await db.audit(who.actor, f"Unreachable hosts are now reported after {unreachable_minutes} min")
    return {"unreachable_minutes": int(unreachable_minutes)}


# ─── Backups and the secret key ─────────────────────────────────────────────

@action("backups.status", "admin")
async def backup_status(who: Principal) -> dict:
    """The last backup and the secret key's state at this process's start."""
    raw = await db.fetchval("SELECT value FROM settings WHERE key = 'backup_status'")
    status = None
    try:
        if raw:
            status = json.loads(raw)
            status["when"] = datetime.fromisoformat(status["at"].replace("Z", "+00:00"))
            status["overdue"] = datetime.now(timezone.utc) - status["when"] > timedelta(
                hours=notify.BACKUP_OVERDUE_HOURS)
    except (ValueError, KeyError, TypeError):
        status = None
    return {"backup": status, "secret_key": dict(security.KEY_STATUS, previous_keys=len(config.SECRET_KEY_PREVIOUS),
                                                  problem=security.key_problem())}


# ─── HTTPS ──────────────────────────────────────────────────────────────────

def _cert_out() -> Optional[dict]:
    info = tls.current() if config.TLS_ON else None
    if not info:
        return None
    return {"subject": info.subject, "issuer": info.issuer, "names": info.names, "not_after": info.not_after,
            "self_signed": info.self_signed, "sha256": info.sha256, "spki_pin": info.spki_pin}


def cert_change_hosts(rows: list[dict], current_pin: Optional[str]) -> list[dict]:
    """Agents that may not trust the current certificate: a different pin was last seen,
    or FleetWright has no pin recorded for them (say so rather than guessing)."""
    if not current_pin:
        return []
    out = []
    for row in rows:
        pin = row.get("agent_tls_pin") or ""
        if pin == current_pin:
            continue
        out.append({"id": row.get("id"), "name": row["name"], "connected": bool(row.get("agent_connected")),
                    "last_seen": row.get("last_seen"), "pin": pin or None,
                    "state": "old_pin" if pin else "unknown"})
    return out


@action("https.get", "admin")
async def https_status(who: Principal) -> dict:
    """The certificate FleetWright serves, the pin agents use, and hosts that may need re-enrolling."""
    cert = _cert_out()
    pin = cert["spki_pin"] if cert else ""
    rows = await db.fetch("""SELECT id, name, agent_connected, last_seen, agent_tls_pin
                             FROM hosts WHERE mode = 'agent' ORDER BY name""") if pin else []
    return {"tls": config.TLS_ON, "certificate": cert, "public_url": config.PUBLIC_URL,
            "agents_connected": len(gateway.connected),
            "reenrol": {"available": bool(pin), "pin": pin or None, "hosts": cert_change_hosts(rows, pin)}}


async def _apply_new_cert(who: Principal, what: str) -> dict:
    """Hand the new certificate to connected agents, then restart to serve it."""
    sent = await gateway.push_trust(tls.leaf_pem())
    await db.audit(who.actor, f"{what}; sent it to {sent} connected agent{'s' if sent != 1 else ''}")
    log.warning("%s; restarting to serve it", what)
    # The container's restart policy brings the web process straight back with the new certificate.
    asyncio.get_running_loop().call_later(1.5, os._exit, 3)
    return {"certificate": _cert_out(), "agents_told": sent, "restarting": True}


def _need_tls() -> None:
    if not config.TLS_ON:
        raise invalid("FleetWright isn't serving HTTPS itself (FLEETWRIGHT_TLS=off).")


@action("https.upload", "admin")
async def https_upload(who: Principal, cert_pem: str, key_pem: str) -> dict:
    """Install your own certificate (with any chain) and key; agents get it first, then FleetWright restarts."""
    _need_tls()
    try:
        if not (cert_pem or "").strip() or not (key_pem or "").strip():
            raise tls.CertProblem("Give both the certificate (with any chain) and its private key.")
        tls.install_uploaded(cert_pem.strip() + "\n", key_pem.strip() + "\n")
    except tls.CertProblem as e:
        raise invalid(str(e)) from e
    return await _apply_new_cert(who, "Uploaded a new HTTPS certificate")


@action("https.regenerate", "admin")
async def https_regenerate(who: Principal, names: Optional[list[str]] = None) -> dict:
    """Make a new self-signed certificate (with extra names); agents get it first, then FleetWright restarts."""
    _need_tls()
    tls.generate_self_signed(list(names or []))
    return await _apply_new_cert(who, "Generated a new self-signed HTTPS certificate")
