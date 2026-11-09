"""
web.py
~~~~~~
The dashboard and the agent gateway, in one FastAPI app:

    uvicorn fleetwright.web:app --host 0.0.0.0 --port 8080

Everyone signs in. Admins manage keys, users and settings; operators run
updates and edit schedules; viewers look. The first visit with no
accounts asks for the setup code printed in this process's log.
"""

from __future__ import annotations

import asyncio
import logging
import secrets
import time
from collections import defaultdict, deque
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import HTMLResponse, PlainTextResponse
from fastapi.staticfiles import StaticFiles
from starlette.middleware.sessions import SessionMiddleware

from . import config, db, gateway, security
from .views import hosts as hosts_views
from .views import runs as runs_views
from .views import schedules as schedule_views
from .views import settings as settings_views
from .webcommon import flash, form_data, redirect, render

log = logging.getLogger("fleetwright.web")

OPEN_PATHS = ("/login", "/setup", "/welcome/", "/static/", "/agent/", "/api/agent/", "/healthz")
_setup_code: list[str] = []
_failures: dict[str, deque] = defaultdict(deque)
FAILURE_LIMIT, FAILURE_WINDOW = 5, 15 * 60


@asynccontextmanager
async def lifespan(_app: FastAPI):
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    problem = security.secret_key_problem()
    if problem:
        raise SystemExit(problem)
    await db.open_pool(max_size=20)
    await db.migrate()
    bg = await gateway.startup()
    if not await db.fetchval("SELECT COUNT(*) FROM users"):
        _the_setup_code()
    yield
    for t in bg:
        t.cancel()
    await db.close_pool()


app = FastAPI(title="FleetWright", lifespan=lifespan, docs_url=None, redoc_url=None, openapi_url=None)
app.mount("/static", StaticFiles(directory=str(Path(__file__).parent / "static")), name="static")
app.include_router(gateway.router)
for module in (hosts_views, runs_views, schedule_views, settings_views):
    app.include_router(module.router)


@app.middleware("http")
async def sign_in_guard(request: Request, call_next):
    request.state.user = None
    path = request.url.path
    if path.startswith(OPEN_PATHS):
        return await call_next(request)
    if not await db.fetchval("SELECT EXISTS (SELECT 1 FROM users)"):
        return redirect("/setup")
    uid = request.session.get("uid")
    u = await db.fetchone("SELECT id, email, name, role FROM users WHERE id = %s", uid) if uid else None
    if not u:
        request.session.pop("uid", None)
        nxt = path + (f"?{request.url.query}" if request.url.query else "")
        return redirect(f"/login?next={nxt}" if path != "/" else "/login")
    request.state.user = u
    return await call_next(request)


app.add_middleware(SessionMiddleware, secret_key=security.session_secret() if config.SECRET_KEY else "unset",
                   session_cookie="fleetwright_session", same_site="lax", https_only=config.SECURE_COOKIES,
                   max_age=14 * 24 * 3600)


@app.exception_handler(HTTPException)
async def http_error(request: Request, exc: HTTPException):
    if request.url.path.startswith(("/api/", "/agent/")):
        return PlainTextResponse(str(exc.detail), status_code=exc.status_code)
    return render(request, "error.html", http_status=exc.status_code, code=exc.status_code, message=exc.detail)


@app.exception_handler(RequestValidationError)
async def bad_request(request: Request, exc: RequestValidationError):
    """A malformed query string or path gets the normal error page, not FastAPI's JSON."""
    if request.url.path.startswith(("/api/", "/agent/")):
        return PlainTextResponse("Bad request", status_code=400)
    return render(request, "error.html", http_status=400, code=400,
                  message="Part of that address isn't valid. Go back and try the link again.")


@app.get("/healthz")
async def healthz():
    await db.fetchval("SELECT 1")
    return {"ok": True, "agents_connected": len(gateway.connected)}


# ─── Signing in ─────────────────────────────────────────────────────────────

def _safe_next(target: str | None) -> str:
    if not target or not target.startswith("/") or target.startswith("//"):
        return "/"
    return target


def _sign_in(request: Request, user_id: int) -> None:
    csrf = request.session.get("csrf")
    request.session.clear()
    request.session["uid"] = user_id
    if csrf:
        request.session["csrf"] = csrf


def _throttled(key: str) -> bool:
    now = time.monotonic()
    q = _failures[key]
    while q and now - q[0] > FAILURE_WINDOW:
        q.popleft()
    return len(q) >= FAILURE_LIMIT


@app.get("/login", response_class=HTMLResponse)
async def login_page(request: Request, next: str = "/"):
    if not await db.fetchval("SELECT EXISTS (SELECT 1 FROM users)"):
        return redirect("/setup")
    return render(request, "login.html", email="", next=_safe_next(next), error=None)


@app.post("/login")
async def login(request: Request):
    form = await form_data(request)
    email = str(form.get("email", "")).strip().lower()
    nxt = _safe_next(form.get("next"))
    key = f"{request.client.host if request.client else ''}|{email}"
    if _throttled(key):
        error = "Too many attempts. Wait 15 minutes, or ask an admin for a setup link."
    else:
        row = await db.fetchone("SELECT id, password_hash FROM users WHERE email = %s", email)
        if security.check_password(row["password_hash"] if row else None, str(form.get("password", ""))) and row:
            _failures.pop(key, None)
            await db.execute("UPDATE users SET last_login = NOW() WHERE id = %s", row["id"])
            _sign_in(request, row["id"])
            return redirect(nxt)
        _failures[key].append(time.monotonic())
        error = "That email and password don't match an account."
    return render(request, "login.html", email=email, next=nxt, error=error, http_status=401)


@app.post("/logout")
async def logout(request: Request):
    await form_data(request)
    request.session.clear()
    return redirect("/login")


def _the_setup_code() -> str:
    if not _setup_code:
        code = "-".join(secrets.token_hex(3) for _ in range(3))
        _setup_code.append(code)
        log.warning("First run: no accounts yet. Open the dashboard and enter this setup code "
                    "to create the first admin: %s", code)
    return _setup_code[0]


@app.get("/setup", response_class=HTMLResponse)
async def setup_page(request: Request):
    if await db.fetchval("SELECT EXISTS (SELECT 1 FROM users)"):
        return redirect("/login")
    _the_setup_code()
    return render(request, "setup.html", form={}, error=None)


@app.post("/setup")
async def setup(request: Request):
    if await db.fetchval("SELECT EXISTS (SELECT 1 FROM users)"):
        return redirect("/login")
    form = await form_data(request)
    code = _the_setup_code()
    error = None
    if not secrets.compare_digest(str(form.get("code", "")).strip().lower(), code):
        error = "That isn't the setup code. It's in the web container's log."
    elif not str(form.get("name", "")).strip() or "@" not in str(form.get("email", "")):
        error = "Enter your name and email."
    else:
        error = security.password_problem(str(form.get("password", "")))
    if error:
        return render(request, "setup.html", form=form, error=error, http_status=400)
    uid = await db.fetchval(
        """INSERT INTO users (email, name, role, password_hash, last_login)
           VALUES (lower(%s), %s, 'admin', %s, NOW()) RETURNING id""",
        str(form["email"]).strip(), str(form["name"]).strip(), security.hash_password(str(form["password"])))
    await db.audit(str(form["name"]).strip(), "Created the first admin account")
    _setup_code.clear()
    _sign_in(request, uid)
    flash(request, "Your admin account is ready. Next: add an SSH key or an enrolment token, then hosts.")
    return redirect("/settings/keys")


@app.get("/welcome/{token}", response_class=HTMLResponse)
async def welcome_page(request: Request, token: str):
    person = await db.fetchone("SELECT id, name, email FROM users WHERE setup_token = %s AND setup_expires > NOW()",
                               security.token_hash(token))
    return render(request, "welcome.html", person=person, error=None, http_status=200 if person else 404)


@app.post("/welcome/{token}")
async def welcome(request: Request, token: str):
    form = await form_data(request)
    person = await db.fetchone("SELECT id, name, email FROM users WHERE setup_token = %s AND setup_expires > NOW()",
                               security.token_hash(token))
    if not person:
        return render(request, "welcome.html", person=None, error=None, http_status=404)
    error = security.password_problem(str(form.get("password", "")), str(form.get("confirm", "")))
    if error:
        return render(request, "welcome.html", person=person, error=error, http_status=400)
    await db.execute("""UPDATE users SET password_hash = %s, setup_token = NULL, setup_expires = NULL,
                               last_login = NOW() WHERE id = %s""",
                     security.hash_password(str(form["password"])), person["id"])
    await db.audit(person["name"], "Set a password from a setup link")
    _sign_in(request, person["id"])
    return redirect("/")


# ─── Overview ───────────────────────────────────────────────────────────────

UNREACHABLE_SQL = ("((h.mode = 'agent' AND NOT h.agent_connected) "
                   "OR (h.mode = 'ssh' AND h.last_error LIKE 'Can''t connect%%'))")


@app.get("/", response_class=HTMLResponse)
async def overview(request: Request):
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
        db.fetchone("""SELECT COUNT(*) FILTER (WHERE current IS NOT NULL) AS pending,
                              COUNT(DISTINCT advisory) FILTER (WHERE is_security) AS advisories,
                              COUNT(DISTINCT host_id) FILTER (WHERE severity = 'critical') AS critical_hosts
                         FROM pending_updates"""),
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
                     ORDER BY rank LIMIT 8"""),
    )
    peak = max([d["hosts"] for d in days] + [1])
    top_os = max([o["n"] for o in oses] + [1])
    return render(request, "overview.html", t=totals, pkgs=pkgs, runs24=runs24, groups=groups,
                  runs=runs, days=days, peak=peak, oses=oses, top_os=top_os, attention=attention)
