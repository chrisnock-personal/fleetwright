"""The UI and the API share one permission model: every action is declared once with its
role (fleetwright/actions), pages never check roles themselves, and every action has an
API route. These tests keep it that way."""

import asyncio
import re
from pathlib import Path

import pytest

from fleetwright import actions
from fleetwright.actions.core import ActionError, Principal, action
from fleetwright.api import api, routes_by_action

ROOT = Path(__file__).resolve().parent.parent / "fleetwright"


def test_pages_never_check_roles_themselves():
    for path in [*(ROOT / "views").glob("*.py"), ROOT / "web.py"]:
        src = path.read_text()
        assert "require(" not in src, f"{path.name} checks a role itself; call an action instead"
        assert not re.search(r"\.can\(", src), f"{path.name} checks a role itself; use may() or an action"


def test_every_action_has_an_api_route():
    missing = sorted(set(actions.ACTIONS) - set(routes_by_action()))
    assert not missing, f"actions with no API route: {missing}"


def test_every_api_route_exposes_an_action():
    unmarked = [r.path for r in api.routes if hasattr(r, "methods") and r.path not in ("/me",)
                and not r.path.startswith(("/openapi", "/docs"))
                and not getattr(r.endpoint, "fleetwright_action", None)]
    assert not unmarked, f"API routes not tied to an action: {unmarked}"


def test_roles_are_as_agreed():
    # Changing one of these is a decision: it changes who may do what, in the UI and the API.
    expected = {
        "viewer": {"hosts.list", "hosts.get", "hosts.pending", "hosts.history", "runs.list", "runs.get",
                   "runs.task", "policies.list", "policies.get", "policies.preview", "bookings.list",
                   "groups.list", "overview.get", "tokens.list", "tokens.create", "tokens.revoke"},
        "operator": {"hosts.add_ssh", "hosts.edit", "hosts.tag", "hosts.move", "hosts.scan", "runs.start",
                     "runs.pause", "runs.resume", "runs.abort", "runs.retry", "policies.save",
                     "policies.set_enabled", "policies.run_now", "policies.delete", "bookings.create",
                     "bookings.cancel"},
    }
    for name, a in actions.ACTIONS.items():
        want = next((r for r, names in expected.items() if name in names), "admin")
        assert a.role == want, f"{name} is {a.role}, expected {want}"


def test_an_action_refuses_a_lower_role():
    @action("test.only_admins", "admin")
    async def only_admins(who):
        return "done"
    try:
        viewer = Principal(1, "Vic", "viewer", token_id=7, token_name="dashboard")
        with pytest.raises(ActionError) as e:
            asyncio.run(only_admins(viewer))
        assert e.value.status == 403 and "Admin" in e.value.message
        assert asyncio.run(only_admins(Principal(2, "Ada", "admin"))) == "done"
        assert viewer.actor == "Vic (token dashboard)"
    finally:
        actions.ACTIONS.pop("test.only_admins")


def test_openapi_document_builds():
    spec = api.openapi()
    assert spec["info"]["title"] == "FleetWright API"
    assert "/runs" in spec["paths"] and "post" in spec["paths"]["/runs"]
    assert "/runs/{run_id}/events" in spec["paths"]
    assert len(spec["paths"]) >= 45
