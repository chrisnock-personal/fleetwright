"""
api.py
~~~~~~
FleetWright's REST API, mounted at /api/v1. Everything the web pages can do, as
JSON, with the same roles: each route calls the same action (actions/) the page
does, and the action checks the role.

Authentication: ``Authorization: Bearer fwt_…``, an API token made on the Account
page or with POST /tokens. Session cookies are not accepted here, so a page on
another site can't make a signed-in browser call the API.

    errors       {"error": {"code": "not_found", "message": "No such host", "errors": [...]}}
    paging       list endpoints take limit and a cursor, and return next_cursor (null at the end)
    retries      Idempotency-Key on anything that starts a run: the same key returns the first answer
    following    GET /runs/{id}/events streams a run's tasks and logs (Server-Sent Events)
    spec         /api/v1/openapi.json, browsable at /api/v1/docs
"""

from __future__ import annotations

import asyncio
import json
import time
from datetime import datetime
from typing import Any, Awaitable, Callable, Literal, Optional

from fastapi import Depends, FastAPI, Header, Query, Request
from fastapi.encoders import jsonable_encoder
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse, StreamingResponse
from pydantic import BaseModel, ConfigDict, Field
from starlette.exceptions import HTTPException as StarletteHTTPException

from . import config, db
from .actions import admin, hosts, runs, schedules, tokens
from .actions.core import ActionError, Principal

VERSION = "1"
RATE_PER_MIN = int(getattr(config, "API_RATE_PER_MIN", 0) or 600)
BURST = 120

api = FastAPI(title="FleetWright API", version=VERSION, docs_url="/docs", redoc_url=None,
              openapi_url="/openapi.json",
              description=("Everything FleetWright's web pages can do, with the same roles. Authenticate with "
                           "`Authorization: Bearer <token>`; make a token on your Account page."))


# ─── Errors ─────────────────────────────────────────────────────────────────

def error(status: int, code: str, message: str, errors: Optional[list] = None, headers: Optional[dict] = None):
    return JSONResponse({"error": {"code": code, "message": message, "errors": errors or [message]}},
                        status_code=status, headers=headers)


@api.exception_handler(ActionError)
async def _action_error(_request: Request, exc: ActionError):
    return error(exc.status, exc.code, exc.message, exc.errors)


@api.exception_handler(RequestValidationError)
async def _validation_error(_request: Request, exc: RequestValidationError):
    errs = [f"{'.'.join(str(p) for p in e['loc'] if p != 'body')}: {e['msg']}" for e in exc.errors()]
    return error(400, "invalid", "The request isn't valid: " + "; ".join(errs), errs)


@api.exception_handler(StarletteHTTPException)
async def _http_error(_request: Request, exc: StarletteHTTPException):
    code = {401: "unauthorized", 403: "forbidden", 404: "not_found", 405: "method_not_allowed",
            429: "rate_limited"}.get(exc.status_code, "error")
    return error(exc.status_code, code, str(exc.detail), headers=getattr(exc, "headers", None))


# ─── Who's calling, and how often ───────────────────────────────────────────

_buckets: dict[int, list[float]] = {}


def _take(token_id: int) -> float:
    """A token bucket per API token: 0 if the request may go ahead, else seconds to wait."""
    now = time.monotonic()
    tokens_left, last = _buckets.get(token_id, [float(BURST), now])
    tokens_left = min(BURST, tokens_left + (now - last) * RATE_PER_MIN / 60)
    if tokens_left < 1:
        _buckets[token_id] = [tokens_left, now]
        return (1 - tokens_left) * 60 / RATE_PER_MIN
    _buckets[token_id] = [tokens_left - 1, now]
    return 0.0


async def principal(authorization: str = Header(default="", description="Bearer fwt_…")) -> Principal:
    token = authorization[7:].strip() if authorization.lower().startswith("bearer ") else ""
    who = await tokens.authenticate(token) if token else None
    if not who:
        raise StarletteHTTPException(401, "Send a valid API token: Authorization: Bearer fwt_…",
                                     headers={"WWW-Authenticate": "Bearer"})
    wait = _take(who.token_id)
    if wait:
        raise StarletteHTTPException(429, f"Too many requests for this token; try again in {wait:.0f} s",
                                     headers={"Retry-After": str(max(1, round(wait)))})
    return who


Who = Depends(principal)


def uses(name: str):
    """Marks which action a route exposes (tests check every action has a route)."""
    def mark(fn):
        fn.fleetwright_action = name
        return fn
    return mark


def ok(data: Any, status: int = 200) -> JSONResponse:
    return JSONResponse(jsonable_encoder(data), status_code=status)


async def idempotent(who: Principal, key: Optional[str], endpoint: str,
                     start: Callable[[], Awaitable[dict]]) -> JSONResponse:
    """With an Idempotency-Key, a repeat of the same request returns the first answer
    instead of doing it again (for a day)."""
    if not key:
        return ok(await start(), 201)
    if len(key) > 200:
        raise ActionError("invalid", "Idempotency-Key is at most 200 characters")
    seen = await db.fetchone("SELECT endpoint, response FROM api_idempotency WHERE token_id = %s AND key = %s "
                             "AND created_at > NOW() - INTERVAL '1 day'", who.token_id, key)
    if seen:
        if seen["endpoint"] != endpoint:
            raise ActionError("conflict", "That Idempotency-Key was already used for a different request")
        return JSONResponse(seen["response"], status_code=200, headers={"Idempotent-Replayed": "true"})
    result = jsonable_encoder(await start())
    await db.execute("""INSERT INTO api_idempotency (token_id, key, endpoint, response) VALUES (%s, %s, %s, %s)
                        ON CONFLICT (token_id, key) DO UPDATE SET endpoint = EXCLUDED.endpoint,
                               response = EXCLUDED.response, created_at = NOW()""",
                     who.token_id, key, endpoint, db.J(result))
    return JSONResponse(result, status_code=201)


IdemKey = Header(default=None, alias="Idempotency-Key",
                 description="Any unique string: a retried request with the same key doesn't start a second run")


class Body(BaseModel):
    model_config = ConfigDict(extra="forbid")


# ─── You ────────────────────────────────────────────────────────────────────

@api.get("/me", tags=["account"], summary="Who this token acts as")
async def me(who: Principal = Who):
    return ok({"user_id": who.user_id, "name": who.name, "role": who.role, "token_id": who.token_id,
               "token_name": who.token_name})


class TokenIn(Body):
    name: str
    role: Optional[Literal["viewer", "operator", "admin"]] = Field(None, description="At most your own role")
    expires_days: Optional[int] = Field(None, ge=1, le=3650)


@api.get("/tokens", tags=["account"])
@uses("tokens.list")
async def token_list(everyone: bool = False, who: Principal = Who):
    return ok(await tokens.list_tokens(who, everyone=everyone))


@api.post("/tokens", tags=["account"], status_code=201)
@uses("tokens.create")
async def token_create(body: TokenIn, who: Principal = Who):
    return ok(await tokens.create_token(who, body.name, body.role, body.expires_days), 201)


@api.delete("/tokens/{token_id}", tags=["account"])
@uses("tokens.revoke")
async def token_revoke(token_id: int, who: Principal = Who):
    return ok(await tokens.revoke_token(who, token_id))


# ─── Overview and audit ─────────────────────────────────────────────────────

@api.get("/overview", tags=["overview"])
@uses("overview.get")
async def overview(who: Principal = Who):
    return ok(await admin.overview(who))


@api.get("/audit", tags=["overview"])
@uses("overview.audit")
async def audit(limit: int = Query(100, ge=1, le=1000), cursor: Optional[int] = None, who: Principal = Who):
    rows = (await admin.audit_log(who, limit=limit, before_id=cursor))["entries"]
    return ok({"entries": rows, "next_cursor": rows[-1]["id"] if len(rows) == limit else None})


# ─── Hosts ──────────────────────────────────────────────────────────────────

@api.get("/hosts", tags=["hosts"], summary="Hosts, with the hosts page's filters")
@uses("hosts.list")
async def host_list(status: str = "all", group: str = Query("", description="group id, or 'none'"),
                    os: str = "", mode: str = Query("", description="ssh or agent"), tag: str = "",
                    q: str = Query("", description="host name, address, package or advisory"),
                    limit: int = Query(100, ge=1, le=1000), cursor: Optional[int] = None, who: Principal = Who):
    if status not in hosts.STATUS_FILTERS:
        raise ActionError("invalid", f"status is one of {', '.join(hosts.STATUS_FILTERS)}")
    r = await hosts.list_hosts(who, status=status, group=group, os=os, mode=mode, tag=tag, q=q, limit=limit,
                               after_id=cursor or 0)
    rows = r["hosts"]
    return ok({"hosts": rows, "counts": r["counts"], "total": r["total"],
               "next_cursor": rows[-1]["id"] if len(rows) == limit else None})


class NewHost(Body):
    name: str
    address: str
    port: int = 22


class HostsIn(Body):
    hosts: list[NewHost]
    credential_id: int = Field(description="The stored SSH key to connect with")
    group_id: Optional[int] = None
    tags: list[str] = []


@api.post("/hosts", tags=["hosts"], status_code=201, summary="Add SSH hosts")
@uses("hosts.add_ssh")
async def host_add(body: HostsIn, who: Principal = Who):
    return ok(await hosts.add_ssh(who, [h.model_dump() for h in body.hosts], body.credential_id, body.group_id,
                                  body.tags), 201)


@api.get("/hosts/{host_id}", tags=["hosts"])
@uses("hosts.get")
async def host_get(host_id: int, who: Principal = Who):
    return ok(await hosts.get_host(who, host_id))


class HostEdit(Body):
    name: Optional[str] = None
    address: Optional[str] = None
    port: Optional[int] = None
    credential_id: Optional[int] = None
    group_id: Optional[int] = None
    tags: Optional[list[str]] = None
    held: Optional[list[str]] = Field(None, description='"Never install" package patterns')


@api.patch("/hosts/{host_id}", tags=["hosts"], summary="Change a host; only the fields sent change")
@uses("hosts.edit")
async def host_edit(host_id: int, body: HostEdit, who: Principal = Who):
    return ok(await hosts.edit(who, host_id, **body.model_dump(exclude_unset=True)))


@api.delete("/hosts/{host_id}", tags=["hosts"])
@uses("hosts.delete")
async def host_delete(host_id: int, who: Principal = Who):
    return ok(await hosts.delete(who, [host_id]))


@api.get("/hosts/{host_id}/updates", tags=["hosts"], summary="Pending updates")
@uses("hosts.pending")
async def host_updates(host_id: int, kind: Literal["all", "security", "kernel", "held"] = "all",
                       who: Principal = Who):
    return ok(await hosts.pending(who, host_id, kind))


@api.get("/hosts/{host_id}/history", tags=["hosts"], summary="Package changes and recent tasks")
@uses("hosts.history")
async def host_history(host_id: int, since: Optional[datetime] = None, limit: int = Query(100, ge=1, le=1000),
                       cursor: Optional[int] = None, who: Principal = Who):
    r = await hosts.history(who, host_id, since=since, limit=limit, before_id=cursor)
    r["next_cursor"] = r["changes"][-1]["id"] if len(r["changes"]) == limit else None
    return ok(r)


@api.post("/hosts/{host_id}/forget-host-key", tags=["hosts"])
@uses("hosts.forget_key")
async def host_forget_key(host_id: int, who: Principal = Who):
    return ok(await hosts.forget_key(who, host_id))


class HostIds(Body):
    host_ids: list[int]


class ScanIn(Body):
    host_ids: Optional[list[int]] = Field(None, description="Leave out to scan every host")


@api.post("/hosts/scan", tags=["hosts"])
@uses("hosts.scan")
async def host_scan(body: ScanIn, who: Principal = Who):
    return ok(await hosts.scan(who, body.host_ids))


class TagIn(HostIds):
    tags: list[str]


@api.post("/hosts/tag", tags=["hosts"], summary="Add tags to hosts")
@uses("hosts.tag")
async def host_tag(body: TagIn, who: Principal = Who):
    return ok(await hosts.tag(who, body.host_ids, body.tags))


class MoveIn(HostIds):
    group_id: Optional[int] = None


@api.post("/hosts/move", tags=["hosts"], summary="Move hosts to a group (null: no group)")
@uses("hosts.move")
async def host_move(body: MoveIn, who: Principal = Who):
    return ok(await hosts.move(who, body.host_ids, body.group_id))


@api.post("/hosts/delete", tags=["hosts"], summary="Remove several hosts")
@uses("hosts.delete")
async def host_delete_many(body: HostIds, who: Principal = Who):
    return ok(await hosts.delete(who, body.host_ids))


# ─── Runs ───────────────────────────────────────────────────────────────────

class Target(Body):
    all: bool = False
    hosts: list[int] = []
    groups: list[int] = []
    tags: list[str] = []
    exclude_tags: list[str] = []


class Selection(Body):
    mode: Literal["all", "kinds"] = "all"
    kinds: list[Literal["security", "kernel", "bugfix", "enhancement"]] = []
    min_severity: Optional[Literal["critical", "important", "moderate", "low", ""]] = None
    include: list[str] = []
    exclude: list[str] = []


class Picked(Body):
    name: str
    arch: Optional[str] = None


class RunIn(Body):
    kind: Literal["apply", "reboot", "scan", "auto_off", "agent_update"]
    target: Target = Target()
    selection: Optional[Selection] = Field(None, description="For apply: what to install (default: everything)")
    picked: Optional[dict[int, list[Picked]]] = Field(
        None, description="For apply: {host id: [{name, arch}]}, installed at the versions pending now")
    title: str = ""
    batch_size: int = Field(0, ge=0, description="Hosts at a time (0: all at once)")
    batch_percent: int = Field(0, ge=0, le=100, description="Or a percentage of the hosts at a time")
    canary: bool = Field(False, description="One host on its own first")
    max_failures: int = Field(0, ge=0, description="Stop after this many failed hosts (0: never)")
    reboot: Literal["never", "if_needed", "always"] = "never"


@api.post("/runs", tags=["runs"], status_code=201, summary="Start a run; returns its id straight away")
@uses("runs.start")
async def run_start(body: RunIn, who: Principal = Who, key: Optional[str] = IdemKey):
    async def go():
        picked = {h: [p.model_dump() for p in ps] for h, ps in body.picked.items()} if body.picked else None
        return await runs.start(who, kind=body.kind, target=body.target.model_dump(),
                                selection=body.selection.model_dump(exclude_none=True) if body.selection else None,
                                picked=picked, title=body.title, batch_size=body.batch_size,
                                batch_percent=body.batch_percent, canary=body.canary,
                                max_failures=body.max_failures, reboot=body.reboot)
    return await idempotent(who, key, "POST /runs", go)


@api.get("/runs", tags=["runs"])
@uses("runs.list")
async def run_list(status: str = "", limit: int = Query(50, ge=1, le=500), cursor: Optional[int] = None,
                   who: Principal = Who):
    rows = (await runs.list_runs(who, limit=limit, before_id=cursor or 2**31 - 1, status=status))["runs"]
    return ok({"runs": rows, "next_cursor": rows[-1]["id"] if len(rows) == limit else None})


@api.get("/runs/{run_id}", tags=["runs"], summary="A run, its batches and every host's task")
@uses("runs.get")
async def run_get(run_id: int, who: Principal = Who):
    return ok(await runs.get_run(who, run_id))


@api.get("/tasks/{task_id}", tags=["runs"], summary="One host's task: status, full log, result, package changes")
@uses("runs.task")
async def task_get(task_id: int, who: Principal = Who):
    return ok(await runs.get_task(who, task_id))


@api.post("/runs/{run_id}/pause", tags=["runs"])
@uses("runs.pause")
async def run_pause(run_id: int, who: Principal = Who):
    return ok(await runs.pause(who, run_id))


@api.post("/runs/{run_id}/resume", tags=["runs"])
@uses("runs.resume")
async def run_resume(run_id: int, who: Principal = Who):
    return ok(await runs.resume(who, run_id))


@api.post("/runs/{run_id}/abort", tags=["runs"])
@uses("runs.abort")
async def run_abort(run_id: int, who: Principal = Who):
    return ok(await runs.abort(who, run_id))


@api.post("/runs/{run_id}/retry", tags=["runs"], status_code=201, summary="A new run on the hosts that failed")
@uses("runs.retry")
async def run_retry(run_id: int, who: Principal = Who, key: Optional[str] = IdemKey):
    return await idempotent(who, key, f"POST /runs/{run_id}/retry", lambda: runs.retry(who, run_id))


def _sse(event: str, data: Any) -> bytes:
    return f"event: {event}\ndata: {json.dumps(jsonable_encoder(data))}\n\n".encode()


@api.get("/runs/{run_id}/events", tags=["runs"],
         summary="Follow a run as Server-Sent Events: run, task and log events, then end")
@uses("runs.get")
async def run_events(run_id: int, request: Request, who: Principal = Who):
    await runs.get_run(who, run_id)   # exists, and the role allows reading it

    async def stream():
        seen_status, seen_tasks, log_len = None, {}, {}
        quiet = 0
        while True:
            if await request.is_disconnected():
                return
            run = await db.fetchone("SELECT id, status, note, current_batch FROM runs WHERE id = %s", run_id)
            changed = False
            if run["status"] != seen_status:
                seen_status = run["status"]
                changed = True
                yield _sse("run", run)
            for t in await db.fetch("""SELECT t.id, t.host_id, h.name AS host, t.batch, t.status, t.detail,
                                              length(t.log) AS log_len
                                         FROM tasks t JOIN hosts h ON h.id = t.host_id WHERE t.run_id = %s
                                        ORDER BY t.id""", run_id):
                state = (t["status"], t["detail"])
                if seen_tasks.get(t["id"]) != state:
                    seen_tasks[t["id"]] = state
                    changed = True
                    yield _sse("task", {k: v for k, v in t.items() if k != "log_len"})
                if t["log_len"] > log_len.get(t["id"], 0):
                    text = await db.fetchval("SELECT substr(log, %s) FROM tasks WHERE id = %s",
                                             log_len.get(t["id"], 0) + 1, t["id"])
                    log_len[t["id"]] = t["log_len"]
                    changed = True
                    yield _sse("log", {"task_id": t["id"], "host": t["host"], "text": text})
            if seen_status not in ("running", "paused") and not changed:
                yield _sse("end", {"status": seen_status})
                return
            quiet = 0 if changed else quiet + 1
            if quiet and quiet % 15 == 0:
                yield b": still running\n\n"
            await asyncio.sleep(1)

    return StreamingResponse(stream(), media_type="text/event-stream",
                             headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


# ─── Agents and enrolment ───────────────────────────────────────────────────

@api.get("/agents", tags=["agents"], summary="Agent counts, the version handed out, and enrolment tokens")
@uses("agents.status")
async def agents(who: Principal = Who):
    return ok(await admin.agents_status(who))


@api.post("/agents/update", tags=["agents"], status_code=201,
          summary="Update every agent that differs from this server's (canary, then 10% at a time)")
@uses("agents.update_all")
async def agents_update(who: Principal = Who, key: Optional[str] = IdemKey):
    return await idempotent(who, key, "POST /agents/update", lambda: runs.update_all_agents(who))


class EnrollIn(Body):
    label: str = ""
    group_id: Optional[int] = None
    tags: list[str] = []
    uses: Optional[int] = Field(None, ge=1, description="Leave out for unlimited until it expires")
    days: int = Field(7, ge=1, le=365)


@api.post("/enrolment-tokens", tags=["agents"], status_code=201,
          summary="An enrolment token and its install command, shown once")
@uses("enroll.create")
async def enroll_create(body: EnrollIn, who: Principal = Who):
    return ok(await admin.create_enroll_token(who, **body.model_dump()), 201)


@api.delete("/enrolment-tokens/{token_id}", tags=["agents"])
@uses("enroll.revoke")
async def enroll_revoke(token_id: int, who: Principal = Who):
    return ok(await admin.revoke_enroll_token(who, token_id))


# ─── Policies and bookings ──────────────────────────────────────────────────

class PolicyIn(Body):
    name: str
    enabled: bool = False
    target: Target
    selection: Selection
    repeat: Literal["daily", "weekly", "monthly"] = "daily"
    weekdays: list[int] = Field([], description="0 = Monday; for weekly")
    monthday: int = Field(1, ge=1, le=28)
    at_time: str = Field("02:00", description="HH:MM, UTC")
    window_minutes: int = Field(120, ge=15, le=1440)
    batch_size: int = 0
    batch_percent: int = Field(0, ge=0, le=100)
    canary: bool = False
    max_failures: int = 2
    reboot: Literal["never", "if_needed", "always"] = "if_needed"


@api.get("/policies", tags=["schedules"])
@uses("policies.list")
async def policy_list(who: Principal = Who):
    return ok(await schedules.list_policies(who))


@api.post("/policies", tags=["schedules"], status_code=201)
@uses("policies.save")
async def policy_create(body: PolicyIn, who: Principal = Who):
    return ok(await schedules.save_policy(who, body.model_dump()), 201)


@api.get("/policies/{policy_id}", tags=["schedules"], summary="A policy, what it would install now, its runs")
@uses("policies.get")
async def policy_get(policy_id: int, who: Principal = Who):
    return ok(await schedules.get_policy(who, policy_id))


@api.put("/policies/{policy_id}", tags=["schedules"], summary="Replace a policy's settings")
@uses("policies.save")
async def policy_replace(policy_id: int, body: PolicyIn, who: Principal = Who):
    return ok(await schedules.save_policy(who, body.model_dump(), policy_id))


@api.delete("/policies/{policy_id}", tags=["schedules"])
@uses("policies.delete")
async def policy_delete(policy_id: int, who: Principal = Who):
    return ok(await schedules.delete_policy(who, policy_id))


@api.post("/policies/{policy_id}/enable", tags=["schedules"])
@uses("policies.set_enabled")
async def policy_enable(policy_id: int, who: Principal = Who):
    return ok(await schedules.set_enabled(who, policy_id, True))


@api.post("/policies/{policy_id}/disable", tags=["schedules"])
@uses("policies.set_enabled")
async def policy_disable(policy_id: int, who: Principal = Who):
    return ok(await schedules.set_enabled(who, policy_id, False))


@api.post("/policies/{policy_id}/run", tags=["schedules"], status_code=201, summary="Run a policy now")
@uses("policies.run_now")
async def policy_run(policy_id: int, who: Principal = Who, key: Optional[str] = IdemKey):
    return await idempotent(who, key, f"POST /policies/{policy_id}/run", lambda: schedules.run_now(who, policy_id))


class PreviewIn(Body):
    target: Target
    selection: Selection


@api.post("/policies/preview", tags=["schedules"], summary="What a target and selection would install now")
@uses("policies.preview")
async def policy_preview(body: PreviewIn, who: Principal = Who):
    return ok(await schedules.preview(who, body.target.model_dump(), body.selection.model_dump(exclude_none=True)))


class BookingTarget(Body):
    hosts: list[int] = []
    groups: list[int] = []
    tags: list[str] = []


class BookingIn(Body):
    target: BookingTarget
    window_start: datetime = Field(description="UTC if no offset is given")
    window_end: datetime
    selection: Optional[Selection] = None
    picked: Optional[dict[int, list[Picked]]] = None
    title: str = ""
    on_window_close: Literal["finish_started", "stop", "carry_on"] = "finish_started"
    batch_size: int = Field(1, ge=0)
    reboot: Literal["never", "if_needed", "always"] = "if_needed"
    needs_approval: bool = False


def _utc(dt: datetime) -> datetime:
    from datetime import timezone
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


@api.get("/bookings", tags=["schedules"])
@uses("bookings.list")
async def booking_list(who: Principal = Who):
    return ok(await schedules.list_bookings(who))


@api.post("/bookings", tags=["schedules"], status_code=201, summary="Book a one-off install for a window")
@uses("bookings.create")
async def booking_create(body: BookingIn, who: Principal = Who):
    picked = {h: [p.model_dump() for p in ps] for h, ps in body.picked.items()} if body.picked else None
    return ok(await schedules.book(
        who, target=body.target.model_dump(), picked=picked,
        selection=body.selection.model_dump(exclude_none=True) if body.selection else None,
        window_start=_utc(body.window_start), window_end=_utc(body.window_end), title=body.title,
        on_window_close=body.on_window_close, batch_size=body.batch_size, reboot=body.reboot,
        needs_approval=body.needs_approval), 201)


@api.post("/bookings/{booking_id}/approve", tags=["schedules"])
@uses("bookings.approve")
async def booking_approve(booking_id: int, who: Principal = Who):
    return ok(await schedules.approve(who, booking_id))


@api.post("/bookings/{booking_id}/cancel", tags=["schedules"])
@uses("bookings.cancel")
async def booking_cancel(booking_id: int, who: Principal = Who):
    return ok(await schedules.cancel(who, booking_id))


# ─── Groups, SSH keys, users ────────────────────────────────────────────────

class GroupIn(Body):
    name: str
    description: str = ""


@api.get("/groups", tags=["settings"])
@uses("groups.list")
async def group_list(who: Principal = Who):
    return ok(await admin.list_groups(who))


@api.post("/groups", tags=["settings"], status_code=201)
@uses("groups.save")
async def group_create(body: GroupIn, who: Principal = Who):
    return ok(await admin.save_group(who, body.name, body.description), 201)


@api.put("/groups/{group_id}", tags=["settings"])
@uses("groups.save")
async def group_update(group_id: int, body: GroupIn, who: Principal = Who):
    return ok(await admin.save_group(who, body.name, body.description, group_id))


@api.delete("/groups/{group_id}", tags=["settings"])
@uses("groups.delete")
async def group_delete(group_id: int, who: Principal = Who):
    return ok(await admin.delete_group(who, group_id))


class KeyIn(Body):
    name: str
    username: str = "root"
    private_key: str = Field("", description="Leave out to generate an ed25519 key")


@api.get("/ssh-keys", tags=["settings"])
@uses("keys.list")
async def key_list(who: Principal = Who):
    return ok(await admin.list_keys(who))


@api.post("/ssh-keys", tags=["settings"], status_code=201, summary="Store or generate an SSH key")
@uses("keys.add")
async def key_add(body: KeyIn, who: Principal = Who):
    return ok(await admin.add_key(who, body.name, body.username, body.private_key), 201)


@api.delete("/ssh-keys/{key_id}", tags=["settings"])
@uses("keys.delete")
async def key_delete(key_id: int, who: Principal = Who):
    return ok(await admin.delete_key(who, key_id))


class UserIn(Body):
    email: str
    name: str
    role: Literal["viewer", "operator", "admin"]


class RoleIn(Body):
    role: Literal["viewer", "operator", "admin"]


@api.get("/users", tags=["settings"])
@uses("users.list")
async def user_list(who: Principal = Who):
    return ok(await admin.list_users(who))


@api.post("/users", tags=["settings"], status_code=201, summary="Add someone; returns their setup link once")
@uses("users.add")
async def user_add(body: UserIn, who: Principal = Who):
    return ok(await admin.add_user(who, body.email, body.name, body.role), 201)


@api.patch("/users/{user_id}", tags=["settings"], summary="Change someone's role")
@uses("users.set_role")
async def user_role(user_id: int, body: RoleIn, who: Principal = Who):
    return ok(await admin.set_role(who, user_id, body.role))


@api.post("/users/{user_id}/setup-link", tags=["settings"])
@uses("users.setup_link")
async def user_link(user_id: int, who: Principal = Who):
    return ok(await admin.setup_link(who, user_id))


@api.delete("/users/{user_id}", tags=["settings"])
@uses("users.delete")
async def user_delete(user_id: int, who: Principal = Who):
    return ok(await admin.delete_user(who, user_id))


# ─── Notifications, backups, HTTPS ──────────────────────────────────────────

class ChannelIn(Body):
    name: str
    kind: Literal["email", "webhook", "ntfy"]
    events: list[str]
    config: dict = Field(description="email: host, port, security, username, from, to. webhook, ntfy: url")
    secret: Optional[str] = Field(None, description="SMTP password, webhook signing secret or ntfy token")
    clear_secret: bool = False


@api.get("/notifications", tags=["settings"])
@uses("notifications.list")
async def channel_list(who: Principal = Who):
    return ok(await admin.list_channels(who))


@api.post("/notifications/channels", tags=["settings"], status_code=201)
@uses("notifications.save")
async def channel_create(body: ChannelIn, who: Principal = Who):
    return ok(await admin.save_channel(who, **body.model_dump()), 201)


@api.put("/notifications/channels/{channel_id}", tags=["settings"], summary="Change a channel (kind stays)")
@uses("notifications.save")
async def channel_update(channel_id: int, body: ChannelIn, who: Principal = Who):
    return ok(await admin.save_channel(who, channel_id=channel_id, **body.model_dump()))


@api.post("/notifications/channels/{channel_id}/test", tags=["settings"])
@uses("notifications.test")
async def channel_test(channel_id: int, who: Principal = Who):
    return ok(await admin.test_channel(who, channel_id))


@api.post("/notifications/channels/{channel_id}/enable", tags=["settings"])
@uses("notifications.set_enabled")
async def channel_enable(channel_id: int, who: Principal = Who):
    return ok(await admin.set_channel_enabled(who, channel_id, True))


@api.post("/notifications/channels/{channel_id}/disable", tags=["settings"])
@uses("notifications.set_enabled")
async def channel_disable(channel_id: int, who: Principal = Who):
    return ok(await admin.set_channel_enabled(who, channel_id, False))


@api.delete("/notifications/channels/{channel_id}", tags=["settings"])
@uses("notifications.delete")
async def channel_delete(channel_id: int, who: Principal = Who):
    return ok(await admin.delete_channel(who, channel_id))


class NotifyOptions(Body):
    unreachable_minutes: int = Field(ge=1, le=10080)


@api.put("/notifications/options", tags=["settings"])
@uses("notifications.options")
async def channel_options(body: NotifyOptions, who: Principal = Who):
    return ok(await admin.notification_options(who, body.unreachable_minutes))


@api.get("/backups", tags=["settings"], summary="The last backup, and the secret key's state")
@uses("backups.status")
async def backups(who: Principal = Who):
    return ok(await admin.backup_status(who))


class CertIn(Body):
    cert_pem: str = Field(description="The certificate, followed by any chain")
    key_pem: str


class RegenerateIn(Body):
    names: list[str] = []


@api.get("/https", tags=["settings"])
@uses("https.get")
async def https_get(who: Principal = Who):
    return ok(await admin.https_status(who))


@api.post("/https/certificate", tags=["settings"],
          summary="Install a certificate; agents get it first, then FleetWright restarts")
@uses("https.upload")
async def https_upload(body: CertIn, who: Principal = Who):
    return ok(await admin.https_upload(who, body.cert_pem, body.key_pem), 202)


@api.post("/https/regenerate", tags=["settings"],
          summary="A new self-signed certificate; agents get it first, then FleetWright restarts")
@uses("https.regenerate")
async def https_regenerate(body: RegenerateIn, who: Principal = Who):
    return ok(await admin.https_regenerate(who, body.names), 202)


def routes_by_action() -> dict[str, list[str]]:
    """Which API routes expose each action (for tests and docs)."""
    out: dict[str, list[str]] = {}
    for r in api.routes:
        name = getattr(getattr(r, "endpoint", None), "fleetwright_action", None)
        if name:
            out.setdefault(name, []).append(f"{sorted(r.methods)[0]} /api/v1{r.path}")
    return out
