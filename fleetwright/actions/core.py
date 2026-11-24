"""
actions/core.py
~~~~~~~~~~~~~~~
Every thing a person can do in FleetWright is an action: one async function,
registered with a name and the lowest role allowed to do it. The web pages
and the API both call actions, so the two can't drift apart: neither checks
roles itself (a test makes sure of that), and every action has an API route
(another test).
"""

from __future__ import annotations

import functools
from dataclasses import dataclass
from typing import Any, Awaitable, Callable, Optional

ROLES = {"admin": "Admin", "operator": "Operator", "viewer": "Viewer"}
RANK = {"viewer": 0, "operator": 1, "admin": 2}


@dataclass(frozen=True)
class Principal:
    """Who is acting: a signed-in person, or a person's API token (whose role may
    be lower than theirs)."""
    user_id: int
    name: str
    role: str
    token_id: Optional[int] = None
    token_name: Optional[str] = None

    @property
    def actor(self) -> str:
        """The name the audit log records."""
        return f"{self.name} (token {self.token_name})" if self.token_id else self.name

    def can(self, role: str) -> bool:
        return RANK.get(self.role, -1) >= RANK[role]


class ActionError(Exception):
    """What went wrong, for a person: shown as a message on a page, or returned as
    {"error": {"code", "message", "errors"}} by the API."""
    STATUS = {"invalid": 400, "forbidden": 403, "not_found": 404, "conflict": 409, "unavailable": 503}

    def __init__(self, code: str, message: str, errors: Optional[list[str]] = None):
        super().__init__(message)
        self.code = code
        self.message = message
        self.errors = errors or [message]

    @property
    def status(self) -> int:
        return self.STATUS.get(self.code, 400)


def invalid(errors: list[str] | str) -> ActionError:
    errors = [errors] if isinstance(errors, str) else errors
    return ActionError("invalid", " ".join(errors), errors)


def not_found(what: str) -> ActionError:
    return ActionError("not_found", f"No such {what}")


@dataclass(frozen=True)
class Action:
    name: str
    role: str
    fn: Callable[..., Awaitable[Any]]
    summary: str


ACTIONS: dict[str, Action] = {}


def action(name: str, role: str):
    """Register an action. Its first argument is the Principal; the role is checked
    before it runs."""
    if role not in RANK:
        raise ValueError(role)

    def wrap(fn):
        @functools.wraps(fn)
        async def checked(who: Principal, *args, **kwargs):
            if not who.can(role):
                raise ActionError("forbidden", f"This needs the {ROLES[role]} role.")
            return await fn(who, *args, **kwargs)

        if name in ACTIONS:
            raise ValueError(f"action {name} registered twice")
        checked.action_name = name
        checked.role = role
        ACTIONS[name] = Action(name, role, checked, (fn.__doc__ or "").strip().split("\n")[0])
        return checked
    return wrap
