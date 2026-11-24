"""FleetWright's actions: everything a person can do, each declared once with its
lowest role, and called by both the web pages and the API. See core.py."""

from . import admin, hosts, runs, schedules, tokens  # noqa: F401 - registers the actions
from .core import ACTIONS, RANK, ROLES, ActionError, Principal  # noqa: F401
