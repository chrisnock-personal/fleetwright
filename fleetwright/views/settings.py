"""Settings (admins): SSH keys, groups, agent enrolment tokens, users and the audit log."""

from __future__ import annotations

import asyncio
import logging
import os
from datetime import datetime, timedelta, timezone

import asyncssh
from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import HTMLResponse

from .. import config, db, gateway, notify, security, tls
from ..db import J
from ..webcommon import ROLES, as_list, flash, form_data, redirect, render, require, split_words

router = APIRouter()
log = logging.getLogger("fleetwright.settings")
SETUP_LINK_HOURS = 72


@router.get("/settings")
async def settings_home(request: Request):
    require(request, "admin")
    return redirect("/settings/keys")


# ─── SSH keys ───────────────────────────────────────────────────────────────

@router.get("/settings/keys", response_class=HTMLResponse)
async def keys_page(request: Request):
    require(request, "admin")
    keys = await db.fetch("""SELECT c.*, (SELECT COUNT(*) FROM hosts h WHERE h.credential_id = c.id) AS hosts
                               FROM ssh_credentials c ORDER BY name""")
    return render(request, "settings_keys.html", keys=keys, section="keys", error=None, form={})


@router.post("/settings/keys")
async def key_add(request: Request):
    form = await form_data(request)
    u = require(request, "admin")
    name = str(form.get("name", "")).strip()
    username = str(form.get("username", "")).strip() or "root"
    pasted = str(form.get("private_key", "")).strip()
    error = None
    if not name:
        error = "Give the key a name."
    try:
        key = asyncssh.import_private_key(pasted) if pasted else asyncssh.generate_private_key("ssh-ed25519")
    except (asyncssh.KeyImportError, ValueError) as e:
        key, error = None, error or f"That private key can't be read ({e}). Keys with a passphrase aren't supported."
    if error:
        keys = await db.fetch("SELECT c.*, 0 AS hosts FROM ssh_credentials c ORDER BY name")
        return render(request, "settings_keys.html", keys=keys, section="keys", error=error, form=form, http_status=400)
    public = key.export_public_key().decode().strip() + f" fleetwright-{name}"
    try:
        await db.execute("""INSERT INTO ssh_credentials (name, username, private_key_enc, public_key)
                            VALUES (%s, %s, %s, %s)""",
                         name, username, security.encrypt(key.export_private_key().decode()), public)
    except Exception as e:
        if "unique" in str(e).lower():
            flash(request, "A key with that name already exists.", "bad")
            return redirect("/settings/keys")
        raise
    await db.audit(u["name"], f"{'Added' if pasted else 'Generated'} SSH key {name} (user {username})")
    flash(request, "Saved. Put the public key below in ~/.ssh/authorized_keys for that user on each host."
          if not pasted else "Saved.")
    return redirect("/settings/keys")


@router.post("/settings/keys/{kid}/delete")
async def key_delete(request: Request, kid: int):
    await form_data(request)
    u = require(request, "admin")
    k = await db.fetchone("SELECT name FROM ssh_credentials WHERE id = %s", kid)
    if k:
        await db.execute("DELETE FROM ssh_credentials WHERE id = %s", kid)
        await db.audit(u["name"], f"Deleted SSH key {k['name']}")
        flash(request, f"Deleted {k['name']}. Hosts that used it need another key.", "info")
    return redirect("/settings/keys")


# ─── Groups ─────────────────────────────────────────────────────────────────

@router.get("/settings/groups", response_class=HTMLResponse)
async def groups_page(request: Request):
    require(request, "admin")
    groups = await db.fetch("""SELECT g.*, (SELECT COUNT(*) FROM hosts h WHERE h.group_id = g.id) AS hosts
                                 FROM groups g ORDER BY name""")
    return render(request, "settings_groups.html", groups=groups, section="groups")


@router.post("/settings/groups")
async def group_save(request: Request):
    form = await form_data(request)
    u = require(request, "admin")
    name = str(form.get("name", "")).strip()
    gid = form.get("id")
    if not name:
        flash(request, "Give the group a name.", "bad")
    elif str(gid or "").isdigit():
        await db.execute("UPDATE groups SET name = %s, description = %s WHERE id = %s",
                         name, str(form.get("description", "")), int(gid))
        await db.audit(u["name"], f"Renamed group to {name}")
        flash(request, "Saved.")
    else:
        await db.execute("INSERT INTO groups (name, description) VALUES (%s, %s) ON CONFLICT (name) DO NOTHING",
                         name, str(form.get("description", "")))
        await db.audit(u["name"], f"Added group {name}")
        flash(request, f"Added {name}.")
    return redirect("/settings/groups")


@router.post("/settings/groups/{gid}/delete")
async def group_delete(request: Request, gid: int):
    await form_data(request)
    u = require(request, "admin")
    g = await db.fetchone("SELECT name FROM groups WHERE id = %s", gid)
    if g:
        await db.execute("DELETE FROM groups WHERE id = %s", gid)
        await db.audit(u["name"], f"Deleted group {g['name']}")
        flash(request, f"Deleted {g['name']}; its hosts are now ungrouped.", "info")
    return redirect("/settings/groups")


# ─── Agent enrolment ────────────────────────────────────────────────────────

@router.get("/settings/agents", response_class=HTMLResponse)
async def agents_page(request: Request):
    require(request, "admin")
    tokens = await db.fetch("""SELECT t.*, g.name AS group_name FROM enroll_tokens t
                                 LEFT JOIN groups g ON g.id = t.group_id ORDER BY t.id DESC""")
    groups = await db.fetch("SELECT id, name FROM groups ORDER BY name")
    new = request.session.pop("new_enroll", None)
    agents = await db.fetchone(f"""SELECT COUNT(*) AS n, COUNT(*) FILTER (WHERE agent_connected) AS up,
                                          COUNT(*) FILTER (WHERE {gateway.outdated_sql()}
                                                           AND agent_bundle IS NOT NULL) AS updatable,
                                          COUNT(*) FILTER (WHERE agent_bundle IS NULL) AS too_old
                                     FROM hosts h WHERE mode = 'agent'""")
    command = gateway.install_command(new["token"]) if new else None
    return render(request, "settings_agents.html", tokens=tokens, groups=groups, new=new, section="agents",
                  public_url=config.PUBLIC_URL, agents=agents, command=command,
                  server_agent=gateway.agent_bundle(), plain_http=config.PUBLIC_URL.startswith("http://"))


@router.post("/settings/agents/update")
async def agents_update(request: Request):
    await form_data(request)
    u = require(request, "admin")
    ids = [r["id"] for r in await db.fetch("SELECT id FROM hosts WHERE mode = 'agent'")]
    run_id = await gateway.start_agent_update(u["name"], ids)
    if run_id is None:
        flash(request, "Every agent that can update itself already matches this server.", "info")
        return redirect("/settings/agents")
    return redirect(f"/runs/{run_id}")


@router.post("/settings/agents")
async def token_add(request: Request):
    form = await form_data(request)
    u = require(request, "admin")
    token = security.new_token(24)
    days = int(form["days"]) if str(form.get("days", "")).isdigit() else 7
    uses = int(form["uses"]) if str(form.get("uses", "")).isdigit() and int(form["uses"]) > 0 else None
    gid = int(form["group_id"]) if str(form.get("group_id", "")).isdigit() else None
    label = str(form.get("label", "")).strip() or "enrolment token"
    await db.execute("""INSERT INTO enroll_tokens (token_hash, label, group_id, tags, uses_left, expires_at, created_by)
                        VALUES (%s, %s, %s, %s, %s, %s, %s)""",
                     security.token_hash(token), label, gid, split_words(form.get("tags")), uses,
                     datetime.now(timezone.utc) + timedelta(days=max(1, min(days, 365))), u["name"])
    await db.audit(u["name"], f"Created enrolment token '{label}'")
    request.session["new_enroll"] = {"token": token, "label": label}
    return redirect("/settings/agents")


@router.post("/settings/agents/{tid}/revoke")
async def token_revoke(request: Request, tid: int):
    await form_data(request)
    u = require(request, "admin")
    await db.execute("UPDATE enroll_tokens SET expires_at = NOW() WHERE id = %s AND expires_at > NOW()", tid)
    await db.audit(u["name"], f"Revoked enrolment token #{tid}")
    flash(request, "Revoked. Agents already enrolled with it keep working.", "info")
    return redirect("/settings/agents")


# ─── Notifications ──────────────────────────────────────────────────────────

@router.get("/settings/notifications", response_class=HTMLResponse)
async def notifications_page(request: Request):
    require(request, "admin")
    channels = await db.fetch("""SELECT c.*, (SELECT COUNT(*) FROM notify_outbox o WHERE o.channel_id = c.id
                                              AND o.sent_at IS NULL) AS queued
                                   FROM notify_channels c ORDER BY name""")
    grace = await db.fetchval("SELECT value FROM settings WHERE key = 'notify_unreachable_min'")
    return render(request, "settings_notifications.html", channels=channels, section="notifications",
                  events=notify.EVENTS, kinds=notify.KINDS, default_events=notify.DEFAULT_EVENTS,
                  grace=int(grace or notify.UNREACHABLE_GRACE_DEFAULT), public_url=config.PUBLIC_URL)


def _channel_config(kind: str, form) -> tuple[dict, list[str]]:
    errors = []
    if kind == "email":
        cfg = {k: str(form.get(k, "")).strip() for k in ("host", "port", "security", "username", "from", "to")}
        if cfg["security"] not in ("starttls", "ssl", "none"):
            cfg["security"] = "starttls"
        if cfg["port"] and not cfg["port"].isdigit():
            errors.append("The SMTP port is a number.")
        if not cfg["host"] or not cfg["from"] or not cfg["to"]:
            errors.append("An email channel needs an SMTP server, a From address and a To address.")
    else:
        cfg = {"url": str(form.get("url", "")).strip()}
        if not cfg["url"].startswith(("https://", "http://")):
            errors.append("The URL must start with https:// (or http://).")
    return cfg, errors


@router.post("/settings/notifications")
async def channel_save(request: Request):
    form = await form_data(request)
    u = require(request, "admin")
    cid = int(form["id"]) if str(form.get("id", "")).isdigit() else None
    old = await db.fetchone("SELECT * FROM notify_channels WHERE id = %s", cid) if cid else None
    kind = old["kind"] if old else str(form.get("kind", ""))
    name = str(form.get("name", "")).strip()[:80]
    events = [e for e in as_list(form.get("events")) if e in notify.EVENTS]
    cfg, errors = _channel_config(kind, form) if kind in notify.KINDS else ({}, ["Choose email, webhook or ntfy."])
    if not name:
        errors.append("Give the channel a name.")
    if not events:
        errors.append("Tick at least one thing to be told about.")
    if errors:
        flash(request, " ".join(errors), "bad")
        return redirect("/settings/notifications")
    secret = str(form.get("secret", ""))
    secret_enc = security.encrypt(secret) if secret else (old["secret_enc"] if old and not form.get("clear_secret")
                                                         else None)
    try:
        if old:
            await db.execute("""UPDATE notify_channels SET name = %s, config = %s, secret_enc = %s, events = %s
                                 WHERE id = %s""", name, J(cfg), secret_enc, events, cid)
            await db.audit(u["name"], f"Changed notification channel '{name}'")
        else:
            await db.execute("""INSERT INTO notify_channels (name, kind, config, secret_enc, events, created_by)
                                VALUES (%s, %s, %s, %s, %s, %s)""", name, kind, J(cfg), secret_enc, events, u["name"])
            await db.audit(u["name"], f"Added {kind} notification channel '{name}'")
    except Exception as e:  # noqa: BLE001
        if "unique" in str(e).lower():
            flash(request, f"There's already a channel called {name}.", "bad")
            return redirect("/settings/notifications")
        raise
    flash(request, "Saved. Use “Send test” to check it.")
    return redirect("/settings/notifications")


@router.post("/settings/notifications/{cid}/action")
async def channel_action(request: Request, cid: int):
    form = await form_data(request)
    u = require(request, "admin")
    c = await db.fetchone("SELECT * FROM notify_channels WHERE id = %s", cid)
    if not c:
        raise HTTPException(404)
    action = form.get("action")
    if action == "test":
        try:
            await notify.send_test(c)
        except Exception as e:  # noqa: BLE001 - shown to the admin
            await db.execute("UPDATE notify_channels SET last_error = %s WHERE id = %s", str(e)[:500], cid)
            flash(request, f"The test to {c['name']} failed: {e}", "bad")
        else:
            await db.execute("UPDATE notify_channels SET last_sent_at = NOW(), last_error = NULL WHERE id = %s", cid)
            flash(request, f"Sent a test to {c['name']}.")
    elif action in ("enable", "disable"):
        await db.execute("UPDATE notify_channels SET enabled = %s WHERE id = %s", action == "enable", cid)
        await db.audit(u["name"], f"{'Enabled' if action == 'enable' else 'Disabled'} notification channel '{c['name']}'")
    elif action == "delete":
        await db.execute("DELETE FROM notify_channels WHERE id = %s", cid)
        await db.audit(u["name"], f"Deleted notification channel '{c['name']}'")
        flash(request, f"Deleted {c['name']}.", "info")
    else:
        raise HTTPException(400, "Unknown action")
    return redirect("/settings/notifications")


@router.post("/settings/notifications/options")
async def notification_options(request: Request):
    form = await form_data(request)
    u = require(request, "admin")
    mins = str(form.get("grace", ""))
    if not mins.isdigit() or not 1 <= int(mins) <= 10080:
        flash(request, "Give the wait in minutes, 1 to 10080.", "bad")
        return redirect("/settings/notifications")
    await db.execute("""INSERT INTO settings (key, value) VALUES ('notify_unreachable_min', %s)
                        ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value""", mins)
    await db.audit(u["name"], f"Unreachable hosts are now reported after {mins} min")
    flash(request, "Saved.")
    return redirect("/settings/notifications")


# ─── Users ──────────────────────────────────────────────────────────────────

@router.get("/settings/users", response_class=HTMLResponse)
async def users_page(request: Request):
    require(request, "admin")
    people = await db.fetch("""SELECT id, email, name, role, last_login, setup_expires,
                                      password_hash IS NOT NULL AS active FROM users ORDER BY role, name""")
    link = request.session.pop("new_link", None)
    return render(request, "settings_users.html", people=people, link=link, section="users",
                  public_url=config.PUBLIC_URL)


async def _admins() -> int:
    return await db.fetchval("SELECT COUNT(*) FROM users WHERE role = 'admin'")


@router.post("/settings/users")
async def user_action(request: Request):
    form = await form_data(request)
    u = require(request, "admin")
    action = form.get("action")
    if action == "add":
        email, name, role = str(form.get("email", "")).strip().lower(), str(form.get("name", "")).strip(), \
            form.get("role", "viewer")
        if "@" not in email or not name or role not in ROLES:
            flash(request, "Enter a name, an email and a role.", "bad")
            return redirect("/settings/users")
        token = security.new_token()
        uid = await db.fetchval(
            """INSERT INTO users (email, name, role, setup_token, setup_expires) VALUES (%s,%s,%s,%s,%s)
               ON CONFLICT (email) DO NOTHING RETURNING id""",
            email, name, role, security.token_hash(token),
            datetime.now(timezone.utc) + timedelta(hours=SETUP_LINK_HOURS))
        if not uid:
            flash(request, "Someone already has that email.", "bad")
            return redirect("/settings/users")
        await db.audit(u["name"], f"Added {name} ({role})")
        request.session["new_link"] = {"name": name, "token": token}
        return redirect("/settings/users")
    uid = int(form["id"]) if str(form.get("id", "")).isdigit() else 0
    target = await db.fetchone("SELECT * FROM users WHERE id = %s", uid)
    if not target:
        raise HTTPException(404)
    if action == "role" and form.get("role") in ROLES:
        if target["role"] == "admin" and form["role"] != "admin" and await _admins() <= 1:
            flash(request, "There must always be at least one admin.", "bad")
        else:
            await db.execute("UPDATE users SET role = %s WHERE id = %s", form["role"], uid)
            await db.audit(u["name"], f"Made {target['name']} {ROLES[form['role']]}")
            flash(request, "Saved.")
    elif action == "link":
        token = security.new_token()
        await db.execute("UPDATE users SET setup_token = %s, setup_expires = %s WHERE id = %s",
                         security.token_hash(token), datetime.now(timezone.utc) + timedelta(hours=SETUP_LINK_HOURS),
                         uid)
        await db.audit(u["name"], f"Created a setup link for {target['name']}")
        request.session["new_link"] = {"name": target["name"], "token": token}
    elif action == "delete":
        if target["id"] == u["id"]:
            flash(request, "You can't remove your own account.", "bad")
        elif target["role"] == "admin" and await _admins() <= 1:
            flash(request, "There must always be at least one admin.", "bad")
        else:
            await db.execute("DELETE FROM users WHERE id = %s", uid)
            await db.audit(u["name"], f"Removed {target['name']}")
            flash(request, f"Removed {target['name']}.", "info")
    return redirect("/settings/users")


@router.get("/settings/audit", response_class=HTMLResponse)
async def audit_page(request: Request):
    require(request, "admin")
    rows = await db.fetch("SELECT * FROM audit_log ORDER BY id DESC LIMIT 300")
    return render(request, "settings_audit.html", rows=rows, section="audit")


# ─── HTTPS certificate ──────────────────────────────────────────────────────

@router.get("/settings/https", response_class=HTMLResponse)
async def https_page(request: Request):
    require(request, "admin")
    return render(request, "settings_https.html", section="https", info=tls.current() if config.TLS_ON else None,
                  tls_on=config.TLS_ON, public_url=config.PUBLIC_URL, agents=len(gateway.connected),
                  error=None, restarting=False)


async def _text(value) -> str:
    if hasattr(value, "read"):
        return (await value.read()).decode(errors="replace")
    return str(value or "")


async def _apply_new_cert(request: Request, actor: str, what: str):
    """Hand the new certificate to connected agents, then restart to serve it."""
    sent = await gateway.push_trust(tls.leaf_pem())
    await db.audit(actor, f"{what}; sent it to {sent} connected agent{'s' if sent != 1 else ''}")
    log.warning("%s; restarting to serve it", what)
    # The container's restart policy brings the web process straight back with the new certificate.
    asyncio.get_running_loop().call_later(1.5, os._exit, 3)
    return render(request, "settings_https.html", section="https", info=tls.current(), tls_on=True,
                  public_url=config.PUBLIC_URL, agents=sent, error=None, restarting=True)


@router.post("/settings/https")
async def https_upload(request: Request):
    form = await form_data(request)
    u = require(request, "admin")
    if not config.TLS_ON:
        raise HTTPException(400, "FleetWright isn't serving HTTPS itself (FLEETWRIGHT_TLS=off).")
    cert_pem = (await _text(form.get("cert_file"))).strip() or str(form.get("cert_pem", "")).strip()
    key_pem = (await _text(form.get("key_file"))).strip() or str(form.get("key_pem", "")).strip()
    try:
        if not cert_pem or not key_pem:
            raise tls.CertProblem("Give both the certificate (with any chain) and its private key.")
        tls.install_uploaded(cert_pem + "\n", key_pem + "\n")
    except tls.CertProblem as e:
        return render(request, "settings_https.html", section="https", info=tls.current(), tls_on=True,
                      public_url=config.PUBLIC_URL, agents=len(gateway.connected), error=str(e),
                      restarting=False, http_status=400)
    return await _apply_new_cert(request, u["name"], "Uploaded a new HTTPS certificate")


@router.post("/settings/https/regenerate")
async def https_regenerate(request: Request):
    form = await form_data(request)
    u = require(request, "admin")
    if not config.TLS_ON:
        raise HTTPException(400, "FleetWright isn't serving HTTPS itself (FLEETWRIGHT_TLS=off).")
    tls.generate_self_signed(split_words(form.get("names")))
    return await _apply_new_cert(request, u["name"], "Generated a new self-signed HTTPS certificate")
