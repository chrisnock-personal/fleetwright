"""
notify.py
~~~~~~~~~
Telling people when something needs them: by email (SMTP), webhook (JSON, Slack
compatible, optionally signed) or ntfy.

Events are written to an outbox, one row per channel that wants them; the worker
sends them every few seconds. Whatever has piled up for a channel goes out as
one message, so an outage that makes 300 hosts unreachable is one message, not
300. A failed send is retried with a growing delay for a day, and the channel
shows the error.
"""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import logging
import smtplib
import ssl
import urllib.error
import urllib.request
from datetime import datetime, timedelta, timezone
from email.message import EmailMessage
from typing import Optional

from . import config, db, security

log = logging.getLogger("fleetwright.notify")

EVENTS = {
    "run_failed": "A run failed, stopped early or missed its window",
    "run_done": "A run finished without problems",
    "unreachable": "A host has been unreachable for a while, and when it's back",
    "approval": "A booked install needs approval",
    "critical": "A critical security update appeared",
    "backup": "A backup failed, or none has been made for over a day",
}
DEFAULT_EVENTS = ["run_failed", "unreachable", "approval", "critical", "backup"]
KINDS = {"email": "Email", "webhook": "Webhook", "ntfy": "ntfy"}
UNREACHABLE_GRACE_DEFAULT = 30          # minutes, a setting on the Notifications page
MAX_ATTEMPTS = 8                        # 1, 2, 4 … 128 minutes apart: about four hours
TIMEOUT = 20


class SendError(Exception):
    pass


# ─── Raising events ─────────────────────────────────────────────────────────

async def emit(event: str, subject: str, body: str, link: Optional[str] = None,
               urgent: bool = False) -> int:
    """Queue a message for every enabled channel that wants this event."""
    return await db.execute(
        """INSERT INTO notify_outbox (channel_id, event, subject, body, link, urgent)
           SELECT id, %s, %s, %s, %s, %s FROM notify_channels WHERE enabled AND %s = ANY(events)""",
        event, subject[:300], body[:8000], link, urgent, event)


def url(path: str) -> str:
    return config.PUBLIC_URL + path


# ─── Composing ──────────────────────────────────────────────────────────────

def compose(items: list[dict]) -> dict:
    """One message from one or more queued events: subject, text, link, urgent."""
    if len(items) == 1:
        i = items[0]
        text = i["body"] + (f"\n\n{i['link']}" if i.get("link") else "")
        return {"subject": i["subject"], "text": text, "link": i.get("link"), "urgent": bool(i.get("urgent")),
                "events": [_plain(i)]}
    urgent = any(i.get("urgent") for i in items)
    lines = []
    for i in items:
        lines.append(f"• {i['subject']}")
        if i["body"] and i["body"] != i["subject"]:
            lines.extend("  " + l for l in i["body"].splitlines()[:6])
        if i.get("link"):
            lines.append(f"  {i['link']}")
    return {"subject": f"FleetWright: {len(items)} things need attention", "text": "\n".join(lines),
            "link": url("/"), "urgent": urgent, "events": [_plain(i) for i in items]}


def _plain(i: dict) -> dict:
    at = i.get("created_at")
    return {"event": i["event"], "subject": i["subject"], "body": i["body"], "link": i.get("link"),
            "at": at.isoformat() if hasattr(at, "isoformat") else at}


def webhook_payload(msg: dict) -> bytes:
    # "text" makes it a valid Slack / Mattermost incoming-webhook message too.
    return json.dumps({"source": "fleetwright", "text": f"*{msg['subject']}*\n{msg['text']}",
                       "subject": msg["subject"], "urgent": msg["urgent"], "link": msg["link"],
                       "events": msg["events"]}).encode()


def signature(secret: str, body: bytes) -> str:
    return "sha256=" + hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()


# ─── Sending (blocking; run in a thread) ────────────────────────────────────

def send(channel: dict, msg: dict) -> None:
    cfg = channel["config"] or {}
    try:
        secret = security.decrypt(channel["secret_enc"]) if channel.get("secret_enc") else ""
    except security.UndecryptableSecret as e:
        raise SendError(str(e)) from e
    kind = channel["kind"]
    if kind == "email":
        _send_email(cfg, secret, msg)
    elif kind == "webhook":
        body = webhook_payload(msg)
        headers = {"Content-Type": "application/json", "User-Agent": "FleetWright"}
        if secret:
            headers["X-FleetWright-Signature"] = signature(secret, body)
        _post(cfg.get("url", ""), body, headers)
    elif kind == "ntfy":
        headers = {"Title": msg["subject"].encode("ascii", "replace").decode(), "User-Agent": "FleetWright",
                   "Priority": "high" if msg["urgent"] else "default",
                   "Tags": "rotating_light" if msg["urgent"] else "package"}
        if msg.get("link"):
            headers["Click"] = msg["link"]
        if secret:
            headers["Authorization"] = f"Bearer {secret}"
        _post(cfg.get("url", ""), msg["text"].encode(), headers)
    else:
        raise SendError(f"unknown kind {kind}")


def _post(target: str, body: bytes, headers: dict) -> None:
    if not target.startswith(("https://", "http://")):
        raise SendError("the URL must start with https:// or http://")
    req = urllib.request.Request(target, data=body, headers=headers, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT) as r:
            r.read(2048)
    except urllib.error.HTTPError as e:
        raise SendError(f"{e.code} {e.reason}: {e.read(300).decode(errors='replace')}".strip()) from e
    except (urllib.error.URLError, OSError) as e:
        raise SendError(f"can't reach {target}: {getattr(e, 'reason', e)}") from e


def _send_email(cfg: dict, password: str, msg: dict) -> None:
    to = [a.strip() for a in str(cfg.get("to", "")).split(",") if a.strip()]
    if not cfg.get("host") or not to or not cfg.get("from"):
        raise SendError("an email channel needs an SMTP server, a From address and at least one To address")
    m = EmailMessage()
    m["Subject"] = msg["subject"]
    m["From"] = cfg["from"]
    m["To"] = ", ".join(to)
    if msg["urgent"]:
        m["X-Priority"] = "1"
    m.set_content(msg["text"])
    port = int(cfg.get("port") or (465 if cfg.get("security") == "ssl" else 587))
    try:
        if cfg.get("security") == "ssl":
            server = smtplib.SMTP_SSL(cfg["host"], port, timeout=TIMEOUT, context=ssl.create_default_context())
        else:
            server = smtplib.SMTP(cfg["host"], port, timeout=TIMEOUT)
        with server:
            if cfg.get("security", "starttls") == "starttls":
                server.starttls(context=ssl.create_default_context())
            if cfg.get("username"):
                server.login(cfg["username"], password)
            server.send_message(m)
    except (smtplib.SMTPException, OSError, ssl.SSLError) as e:
        raise SendError(f"SMTP {cfg['host']}:{port}: {e}") from e


async def send_test(channel: dict) -> None:
    msg = compose([{"event": "test", "subject": "FleetWright test message",
                    "body": f"The notification channel “{channel['name']}” works.", "link": url("/")}])
    await asyncio.to_thread(send, channel, msg)


# ─── Delivering the outbox (the worker) ─────────────────────────────────────

async def deliver() -> None:
    due = await db.fetch("""SELECT DISTINCT channel_id FROM notify_outbox
                             WHERE sent_at IS NULL AND next_try <= NOW()""")
    for row in due:
        channel = await db.fetchone("SELECT * FROM notify_channels WHERE id = %s", row["channel_id"])
        items = await db.fetch("""SELECT * FROM notify_outbox WHERE channel_id = %s AND sent_at IS NULL
                                   AND next_try <= NOW() ORDER BY id LIMIT 50""", row["channel_id"])
        if not channel or not items:
            continue
        ids = [i["id"] for i in items]
        try:
            await asyncio.to_thread(send, channel, compose(items))
        except Exception as e:  # noqa: BLE001 - recorded on the channel, retried
            err = str(e)[:500]
            log.warning("notification channel %s: %s", channel["name"], err)
            await db.execute("UPDATE notify_channels SET last_error = %s WHERE id = %s", err, channel["id"])
            await db.execute("""UPDATE notify_outbox SET attempts = attempts + 1,
                                       next_try = NOW() + make_interval(mins => power(2, attempts)::int),
                                       sent_at = CASE WHEN attempts + 1 >= %s THEN 'epoch' END
                                 WHERE id = ANY(%s)""", MAX_ATTEMPTS, ids)
            continue
        await db.execute("UPDATE notify_outbox SET sent_at = NOW() WHERE id = ANY(%s)", ids)
        await db.execute("UPDATE notify_channels SET last_sent_at = NOW(), last_error = NULL WHERE id = %s",
                         channel["id"])
    await db.execute("DELETE FROM notify_outbox WHERE sent_at < NOW() - INTERVAL '7 days'")


# ─── Unreachable hosts (the worker, once a minute) ──────────────────────────

UNREACHABLE_SQL = ("((h.mode = 'agent' AND NOT h.agent_connected) "
                   "OR (h.mode = 'ssh' AND h.last_error LIKE 'Can''t connect%%'))")


async def check_unreachable() -> None:
    grace = int(await db.fetchval("SELECT value FROM settings WHERE key = 'notify_unreachable_min'")
                or UNREACHABLE_GRACE_DEFAULT)
    gone = await db.fetch(
        f"""UPDATE hosts h SET unreachable_notified = TRUE
             WHERE NOT unreachable_notified AND {UNREACHABLE_SQL}
               AND COALESCE(last_seen, created_at) < NOW() - make_interval(mins => %s)
         RETURNING id, name, last_seen, last_error, mode""", grace)
    back = await db.fetch(f"""UPDATE hosts h SET unreachable_notified = FALSE
                               WHERE unreachable_notified AND NOT {UNREACHABLE_SQL}
                           RETURNING id, name""")
    if gone:
        names = ", ".join(r["name"] for r in gone[:20]) + (f" and {len(gone) - 20} more" if len(gone) > 20 else "")
        lines = [f"{r['name']}: {(r['last_error'] or 'agent not connected')[:120]}" for r in gone[:20]]
        await emit("unreachable",
                   f"{len(gone)} host{'s' if len(gone) != 1 else ''} unreachable: {names}" if len(gone) > 1
                   else f"{gone[0]['name']} is unreachable",
                   f"Unreachable for more than {grace} minute{'s' if grace != 1 else ''}.\n" + "\n".join(lines),
                   url("/hosts?status=unreachable") if len(gone) > 1 else url(f"/hosts/{gone[0]['id']}"),
                   urgent=True)
    if back:
        names = ", ".join(r["name"] for r in back[:20]) + (f" and {len(back) - 20} more" if len(back) > 20 else "")
        await emit("unreachable", f"Reachable again: {names}", "These hosts are answering again.",
                   url(f"/hosts/{back[0]['id']}") if len(back) == 1 else url("/hosts"))


# ─── Backups (the worker, once a minute) ────────────────────────────────────

BACKUP_OVERDUE_HOURS = 26


async def check_backup() -> None:
    """The backup service records each attempt in settings.backup_status; tell people
    once about a failure, and once when backups have stopped altogether."""
    raw = await db.fetchval("SELECT value FROM settings WHERE key = 'backup_status'")
    if not raw:
        return
    try:
        st = json.loads(raw)
        at = datetime.fromisoformat(st["at"].replace("Z", "+00:00"))
    except (ValueError, KeyError, TypeError):
        return
    told = await db.fetchval("SELECT value FROM settings WHERE key = 'backup_notified'")
    key = None
    if not st.get("ok"):
        key = f"failed:{st['at']}"
        subject, body = "Backup failed", f"The backup at {at:%Y-%m-%d %H:%M} UTC failed: {st.get('message') or '?'}"
    elif datetime.now(timezone.utc) - at > timedelta(hours=BACKUP_OVERDUE_HOURS):
        key = f"overdue:{st['at']}"
        subject, body = "No backup for over a day", (f"The last backup was {st.get('file')} at {at:%Y-%m-%d %H:%M} UTC. "
                                                     "Is the backup service running?")
    if key and key != told:
        await emit("backup", subject, body, url("/settings/backups"), urgent=True)
        await db.execute("""INSERT INTO settings (key, value) VALUES ('backup_notified', %s)
                            ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value""", key)
