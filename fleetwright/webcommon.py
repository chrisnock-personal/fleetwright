"""Helpers shared by the web pages: templates, sign-in checks, CSRF, flash messages."""

from __future__ import annotations

import secrets
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional
from urllib.parse import urlencode

from fastapi import HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates

from . import fleet

ROLES = {"admin": "Admin", "operator": "Operator", "viewer": "Viewer"}
RANK = {"viewer": 0, "operator": 1, "admin": 2}

templates = Jinja2Templates(directory=str(Path(__file__).parent / "templates"))


def csrf_token(request: Request) -> str:
    if "csrf" not in request.session:
        request.session["csrf"] = secrets.token_urlsafe(24)
    return request.session["csrf"]


async def form_data(request: Request) -> dict[str, Any]:
    """The posted form, after checking its CSRF token. Repeated fields come back as lists."""
    form = await request.form()
    sent = str(form.get("csrf", ""))
    if not sent or not secrets.compare_digest(sent, request.session.get("csrf", "")):
        raise HTTPException(400, "The form has expired. Go back, reload the page and try again.")
    out: dict[str, Any] = {}
    for key in form.keys():
        values = form.getlist(key)
        out[key] = values if len(values) > 1 or key.endswith("[]") else values[0]
    return out


def as_list(value: Any) -> list[str]:
    if value is None or value == "":
        return []
    return [str(v) for v in value] if isinstance(value, list) else [str(value)]


def split_words(value: Optional[str]) -> list[str]:
    if not value:
        return []
    return [w for w in (part.strip() for part in value.replace("\n", ",").split(",")) if w]


def user(request: Request) -> dict:
    return request.state.user


def require(request: Request, role: str) -> dict:
    u = request.state.user
    if RANK.get(u["role"], -1) < RANK[role]:
        raise HTTPException(403, f"This needs the {ROLES[role]} role.")
    return u


def can(u: Optional[dict], role: str) -> bool:
    return bool(u) and RANK.get(u["role"], -1) >= RANK[role]


def flash(request: Request, message: str, tone: str = "ok") -> None:
    request.session.setdefault("flash", []).append([tone, message])


def redirect(url: str) -> RedirectResponse:
    return RedirectResponse(url, status_code=303)


def render(request: Request, name: str, http_status: int = 200, **ctx: Any) -> HTMLResponse:
    flashes = request.session.pop("flash", []) if "session" in request.scope else []
    base = {"request": request, "current_user": getattr(request.state, "user", None),
            "csrf": csrf_token(request) if "session" in request.scope else "", "flashes": flashes}
    return templates.TemplateResponse(request, name, {**base, **ctx}, status_code=http_status)


# ─── Template filters ───────────────────────────────────────────────────────

def ago(dt: Optional[datetime]) -> str:
    if not dt:
        return "never"
    secs = (datetime.now(timezone.utc) - dt).total_seconds()
    if secs < 0:
        return in_(dt)
    if secs < 60:
        return "just now"
    if secs < 3600:
        return f"{int(secs // 60)} min ago"
    if secs < 86400:
        return f"{int(secs // 3600)} h ago"
    days = int(secs // 86400)
    return "yesterday" if days == 1 else f"{days} days ago"


def in_(dt: Optional[datetime]) -> str:
    if not dt:
        return ""
    secs = (dt - datetime.now(timezone.utc)).total_seconds()
    if secs < 60:
        return "now"
    if secs < 3600:
        return f"in {int(secs // 60)} min"
    if secs < 86400:
        return f"in {int(secs // 3600)} h"
    return f"in {int(secs // 86400)} days"


def when(dt: Optional[datetime], with_year: bool = False) -> str:
    if not dt:
        return "—"
    dt = dt.astimezone(timezone.utc)
    today = datetime.now(timezone.utc).date()
    if dt.date() == today:
        return dt.strftime("%H:%M")
    return dt.strftime("%d %b %Y %H:%M" if with_year or dt.year != today.year else "%a %d %b %H:%M")


def num(n: Any) -> str:
    try:
        return f"{int(n):,}"
    except (TypeError, ValueError):
        return "0"


def qs(request: Request, **changes: Any) -> str:
    """The current query string with some values changed (None removes one)."""
    params = dict(request.query_params)
    for k, v in changes.items():
        if v is None or v == "":
            params.pop(k, None)
        else:
            params[k] = v
    return "?" + urlencode(params) if params else "?"


STATUS_TONE = {"running": "info", "queued": "info", "waiting": "muted", "paused": "warn", "done": "good",
               "failed": "bad", "aborted": "muted", "stopped": "warn", "skipped": "muted",
               "booked": "info", "needs_approval": "warn", "started": "info", "missed": "bad",
               "cancelled": "muted"}
STATUS_LABEL = {"needs_approval": "Needs approval"}


def tone(status: str) -> str:
    return STATUS_TONE.get(status, "muted")


def label(status: str) -> str:
    return STATUS_LABEL.get(status, status.replace("_", " ").capitalize())


templates.env.filters.update(ago=ago, in_=in_, when=when, num=num, tone=tone, label=label)
templates.env.globals.update(can=can, qs=qs, ROLES=ROLES, KIND_LABELS=fleet.KIND_LABELS,
                             REBOOT_CHOICES=fleet.REBOOT_CHOICES, WINDOW_CLOSE=fleet.WINDOW_CLOSE,
                             describe_selection=fleet.describe_selection)
