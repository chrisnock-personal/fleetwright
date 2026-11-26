"""Settings (admins): SSH keys, groups, agents, notifications, backups, users, HTTPS and the
audit log; and everyone's Account page with their API tokens. Roles are checked by the
actions these call (actions/admin.py, actions/tokens.py), not here."""

from __future__ import annotations

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import HTMLResponse

from .. import config, gateway, notify
from ..actions import admin
from ..actions import runs as run_actions
from ..actions import tokens as token_actions
from ..actions.core import ActionError
from ..webcommon import as_list, attempt, flash, form_data, may, redirect, render, split_words, who

router = APIRouter()


def _id(v) -> int | None:
    return int(v) if str(v or "").isdigit() else None


@router.get("/settings")
async def settings_home(request: Request):
    may(request, "keys.list")
    return redirect("/settings/keys")


# ─── SSH keys ───────────────────────────────────────────────────────────────

@router.get("/settings/keys", response_class=HTMLResponse)
async def keys_page(request: Request):
    keys = (await admin.list_keys(who(request)))["keys"]
    return render(request, "settings_keys.html", keys=keys, section="keys", error=None, form={})


@router.post("/settings/keys")
async def key_add(request: Request):
    form = await form_data(request)
    try:
        r = await admin.add_key(who(request), str(form.get("name", "")), str(form.get("username", "")),
                                str(form.get("private_key", "")))
    except ActionError as e:
        if e.code != "invalid":
            raise
        if "already exists" in e.message:
            flash(request, e.message, "bad")
            return redirect("/settings/keys")
        keys = (await admin.list_keys(who(request)))["keys"]
        return render(request, "settings_keys.html", keys=keys, section="keys", error=e.message, form=form,
                      http_status=400)
    flash(request, "Saved. Put the public key below in ~/.ssh/authorized_keys for that user on each host."
          if r["generated"] else "Saved.")
    return redirect("/settings/keys")


@router.post("/settings/keys/{kid}/delete")
async def key_delete(request: Request, kid: int):
    await form_data(request)
    r, bounce = await attempt(request, admin.delete_key(who(request), kid), "/settings/keys")
    if r:
        flash(request, f"Deleted {r['deleted']}. Hosts that used it need another key.", "info")
    return redirect("/settings/keys")


# ─── Groups ─────────────────────────────────────────────────────────────────

@router.get("/settings/groups", response_class=HTMLResponse)
async def groups_page(request: Request):
    may(request, "groups.save")
    groups = (await admin.list_groups(who(request)))["groups"]
    return render(request, "settings_groups.html", groups=groups, section="groups")


@router.post("/settings/groups")
async def group_save(request: Request):
    form = await form_data(request)
    gid = _id(form.get("id"))
    r, bounce = await attempt(request, admin.save_group(who(request), str(form.get("name", "")),
                                                        str(form.get("description", "")), gid), "/settings/groups")
    if r:
        flash(request, "Saved." if gid else f"Added {str(form.get('name', '')).strip()}.")
    return redirect("/settings/groups")


@router.post("/settings/groups/{gid}/delete")
async def group_delete(request: Request, gid: int):
    await form_data(request)
    r, _ = await attempt(request, admin.delete_group(who(request), gid), "/settings/groups")
    if r:
        flash(request, f"Deleted {r['deleted']}; its hosts are now ungrouped.", "info")
    return redirect("/settings/groups")


# ─── Agents and enrolment ───────────────────────────────────────────────────

@router.get("/settings/agents", response_class=HTMLResponse)
async def agents_page(request: Request):
    st = await admin.agents_status(who(request))
    groups = (await admin.list_groups(who(request)))["groups"]
    new = request.session.pop("new_enroll", None)
    a = st["agents"]
    agents = {"n": a["enrolled"], "up": a["connected"], "updatable": a["updatable"], "too_old": a["too_old"]}
    return render(request, "settings_agents.html", tokens=st["tokens"], groups=groups, new=new, section="agents",
                  public_url=config.PUBLIC_URL, agents=agents, command=new and new["command"],
                  server_agent=st["server_agent"], plain_http=config.PUBLIC_URL.startswith("http://"))


@router.post("/settings/agents/update")
async def agents_update(request: Request):
    await form_data(request)
    r, bounce = await attempt(request, run_actions.update_all_agents(who(request)), "/settings/agents")
    return bounce or redirect(f"/runs/{r['run_id']}")


@router.post("/settings/agents")
async def token_add(request: Request):
    form = await form_data(request)
    r = await admin.create_enroll_token(who(request), str(form.get("label", "")), _id(form.get("group_id")),
                                        split_words(form.get("tags")), _id(form.get("uses")),
                                        _id(form.get("days")) or 7)
    request.session["new_enroll"] = {"label": r["label"], "command": r["install_command"]}
    return redirect("/settings/agents")


@router.post("/settings/agents/{tid}/revoke")
async def token_revoke(request: Request, tid: int):
    await form_data(request)
    await admin.revoke_enroll_token(who(request), tid)
    flash(request, "Revoked. Agents already enrolled with it keep working.", "info")
    return redirect("/settings/agents")


# ─── Notifications ──────────────────────────────────────────────────────────

@router.get("/settings/notifications", response_class=HTMLResponse)
async def notifications_page(request: Request):
    r = await admin.list_channels(who(request))
    return render(request, "settings_notifications.html", channels=r["channels"], section="notifications",
                  events=r["events"], kinds=r["kinds"], default_events=notify.DEFAULT_EVENTS,
                  grace=r["unreachable_minutes"], public_url=config.PUBLIC_URL)


CHANNEL_FIELDS = ("host", "port", "security", "username", "from", "to", "url")


@router.post("/settings/notifications")
async def channel_save(request: Request):
    form = await form_data(request)
    back = "/settings/notifications"
    r, bounce = await attempt(request, admin.save_channel(
        who(request), name=str(form.get("name", "")), kind=str(form.get("kind", "")),
        events=as_list(form.get("events")), config={k: form.get(k, "") for k in CHANNEL_FIELDS},
        secret=str(form.get("secret", "")) or None, clear_secret=bool(form.get("clear_secret")),
        channel_id=_id(form.get("id"))), back)
    if r:
        flash(request, "Saved. Use “Send test” to check it.")
    return bounce or redirect(back)


@router.post("/settings/notifications/{cid}/action")
async def channel_action(request: Request, cid: int):
    form = await form_data(request)
    p = who(request)
    action = form.get("action")
    if action == "test":
        r = await admin.test_channel(p, cid)
        if r["sent"]:
            flash(request, "Sent a test message.")
        else:
            flash(request, f"The test failed: {r['error']}", "bad")
    elif action in ("enable", "disable"):
        await admin.set_channel_enabled(p, cid, action == "enable")
    elif action == "delete":
        r = await admin.delete_channel(p, cid)
        flash(request, f"Deleted {r['deleted']}.", "info")
    else:
        raise HTTPException(400, "Unknown action")
    return redirect("/settings/notifications")


@router.post("/settings/notifications/options")
async def notification_options(request: Request):
    form = await form_data(request)
    mins = _id(form.get("grace"))
    r, bounce = await attempt(request, admin.notification_options(who(request), mins if mins else 0),
                              "/settings/notifications")
    if r:
        flash(request, "Saved.")
    return bounce or redirect("/settings/notifications")


# ─── Backups and the secret key ─────────────────────────────────────────────

@router.get("/settings/backups", response_class=HTMLResponse)
async def backups_page(request: Request):
    r = await admin.backup_status(who(request))
    return render(request, "settings_backups.html", section="backups", status=r["backup"],
                  key_status=r["secret_key"], previous=r["secret_key"]["previous_keys"])


# ─── Users ──────────────────────────────────────────────────────────────────

@router.get("/settings/users", response_class=HTMLResponse)
async def users_page(request: Request):
    people = (await admin.list_users(who(request)))["users"]
    link = request.session.pop("new_link", None)
    return render(request, "settings_users.html", people=people, link=link, section="users",
                  public_url=config.PUBLIC_URL)


@router.post("/settings/users")
async def user_action(request: Request):
    form = await form_data(request)
    p = who(request)
    back = "/settings/users"
    action = form.get("action")
    uid = _id(form.get("id")) or 0
    if action == "add":
        r, bounce = await attempt(request, admin.add_user(p, str(form.get("email", "")), str(form.get("name", "")),
                                                          str(form.get("role", "viewer"))), back)
        if r:
            request.session["new_link"] = {"name": r["name"], "token": r["token"]}
        return bounce or redirect(back)
    if action == "role":
        r, bounce = await attempt(request, admin.set_role(p, uid, str(form.get("role", ""))), back)
        if r:
            flash(request, "Saved.")
    elif action == "link":
        r, bounce = await attempt(request, admin.setup_link(p, uid), back)
        if r:
            request.session["new_link"] = {"name": r["name"], "token": r["token"]}
    elif action == "delete":
        r, bounce = await attempt(request, admin.delete_user(p, uid), back)
        if r:
            flash(request, f"Removed {r['deleted']}.", "info")
    return redirect(back)


@router.get("/settings/audit", response_class=HTMLResponse)
async def audit_page(request: Request):
    rows = (await admin.audit_log(who(request), limit=300))["entries"]
    return render(request, "settings_audit.html", rows=rows, section="audit")


# ─── HTTPS certificate ──────────────────────────────────────────────────────

def _https_page(request: Request, r: dict, error=None, restarting=False, status=200):
    from .. import tls
    reenrol = r.get("reenrol") or {"available": False, "pin": None, "hosts": []}
    new = request.session.pop("new_reenroll", None) if "session" in request.scope else None
    return render(request, "settings_https.html", section="https",
                  info=tls.current() if config.TLS_ON else None, tls_on=config.TLS_ON,
                  public_url=config.PUBLIC_URL, agents=r.get("agents_told", r.get("agents_connected", 0)),
                  reenrol=reenrol, reenrol_command=(new or {}).get("command"),
                  command_template=gateway.install_command("<enrolment token>") if reenrol["available"] else "",
                  error=error, restarting=restarting, http_status=status)


@router.get("/settings/https", response_class=HTMLResponse)
async def https_page(request: Request):
    return _https_page(request, await admin.https_status(who(request)))


async def _text(value) -> str:
    if hasattr(value, "read"):
        return (await value.read()).decode(errors="replace")
    return str(value or "")


@router.post("/settings/https")
async def https_upload(request: Request):
    form = await form_data(request)
    cert_pem = (await _text(form.get("cert_file"))).strip() or str(form.get("cert_pem", "")).strip()
    key_pem = (await _text(form.get("key_file"))).strip() or str(form.get("key_pem", "")).strip()
    try:
        r = await admin.https_upload(who(request), cert_pem, key_pem)
    except ActionError as e:
        if e.code != "invalid":
            raise
        return _https_page(request, await admin.https_status(who(request)), error=e.message, status=400)
    return _https_page(request, r, restarting=True)


@router.post("/settings/https/regenerate")
async def https_regenerate(request: Request):
    form = await form_data(request)
    r = await admin.https_regenerate(who(request), split_words(form.get("names")))
    return _https_page(request, r, restarting=True)


@router.post("/settings/https/reenrol")
async def https_reenrol_token(request: Request):
    """Mint the enrolment token for the command shown on the HTTPS page."""
    await form_data(request)
    r = await admin.create_enroll_token(who(request), label="HTTPS re-enrol")
    request.session["new_reenroll"] = {"label": r["label"], "command": r["install_command"]}
    flash(request, "New enrolment token created; it's shown once below. Run it on each host that needs "
                   "re-enrolling, then close this page.")
    return redirect("/settings/https")


# ─── Your account: API tokens ───────────────────────────────────────────────

@router.get("/account", response_class=HTMLResponse)
async def account_page(request: Request):
    p = who(request)
    mine = (await token_actions.list_tokens(p))["tokens"]
    try:
        everyone = (await token_actions.list_tokens(p, everyone=True))["tokens"]
    except ActionError:          # only admins see everyone's
        everyone = []
    new = request.session.pop("new_api_token", None)
    return render(request, "account.html", tokens=mine, others=[t for t in everyone if t["user_id"] != p.user_id],
                  new=new, api_url=config.PUBLIC_URL + "/api/v1")


@router.post("/account/tokens")
async def account_token_add(request: Request):
    form = await form_data(request)
    days = _id(form.get("expires_days"))
    r, bounce = await attempt(request, token_actions.create_token(
        who(request), str(form.get("name", "")), str(form.get("role", "")) or None, days), "/account")
    if r:
        request.session["new_api_token"] = {"name": r["name"], "token": r["token"], "role": r["role"]}
    return bounce or redirect("/account")


@router.post("/account/tokens/{tid}/revoke")
async def account_token_revoke(request: Request, tid: int):
    await form_data(request)
    r = await token_actions.revoke_token(who(request), tid)
    flash(request, f"Revoked {r['revoked']}.", "info")
    return redirect("/account")
