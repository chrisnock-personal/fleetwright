"""Templates ask the action (may('hosts.scan')) instead of checking a role themselves (#41).
The server still checks the same declaration in the action, so a button can't drift from it."""

import re
from datetime import datetime
from pathlib import Path
from types import SimpleNamespace

import pytest

from fleetwright import actions, webcommon
from fleetwright.actions.core import RANK

TEMPLATES = Path(webcommon.__file__).parent / "templates"


@pytest.mark.parametrize("action_name,role", [
    ("hosts.scan", "operator"),
    ("policies.save", "operator"),
    ("bookings.approve", "admin"),
    ("hosts.list", "viewer"),
])
def test_may_uses_the_actions_own_role(action_name, role):
    assert actions.ACTIONS[action_name].role == role
    for r, rank in RANK.items():
        assert webcommon.may({"role": r}, action_name) == (rank >= RANK[role]), r
    assert not webcommon.may(None, action_name)


def test_may_names_an_unknown_action():
    with pytest.raises(ValueError, match="no.such.action"):
        webcommon.may({"role": "admin"}, "no.such.action")


def test_templates_do_not_check_fixed_roles_with_can():
    for path in TEMPLATES.glob("*.html"):
        src = path.read_text()
        assert not re.search(r"can\(current_user,\s*['\"](?:viewer|operator|admin)['\"]\)", src), \
            f"{path.name} checks a role itself; ask the action with may()"


def page(role, **ctx):
    """Render a real template the way webcommon.render() does, with no database involved."""
    return webcommon.templates.env.get_template(ctx.pop("name")).render(
        current_user={"id": 1, "name": "Vic", "email": "vic@example.com", "role": role},
        csrf="token", flashes=[], request=SimpleNamespace(query_params={}), **ctx)


def overview_ctx():
    return dict(name="overview.html", groups=[],
                t={"hosts": 1, "agents": 1, "ssh": 0, "last_scan": None, "with_updates": 0,
                   "with_security": 0, "reboot": 0, "unreachable": 0, "unreachable_agent": 0},
                pkgs={"pending": 0, "advisories": 0, "critical_hosts": 0},
                runs24={"runs": 0, "failed": 0, "active": 0},
                runs=[], days=[{"day": datetime(2026, 11, 26), "hosts": 0, "failed": 0}],
                peak=1, oses=[], top_os="Fedora", attention=[])


def test_a_viewer_sees_no_operator_buttons():
    html = page("viewer", **overview_ctx())
    assert "Scan all" not in html
    assert 'href="/hosts/new">Add hosts' not in html


def test_an_operator_sees_the_operator_buttons():
    html = page("operator", **overview_ctx())
    assert "Scan all" in html
    assert 'href="/hosts/new">Add hosts' in html


def schedules_ctx():
    booking = {"id": 7, "status": "needs_approval", "run_id": None, "approved_by": None,
               "window_start": datetime(2026, 11, 27, 2, 0), "window_end": datetime(2026, 11, 27, 4, 0),
               "title": "Nightly", "target_text": "All hosts", "selection": {"mode": "all"},
               "reboot": "never", "created_by": "Vic"}
    return dict(name="schedules.html", policies=[], bookings=[booking], week=[], booked=1, on_count=0)


def test_an_operator_sees_no_admin_button():
    html = page("operator", **schedules_ctx())
    assert "value=\"approve\"" not in html
    assert "value=\"cancel\"" in html                     # bookings.cancel is an operator action


def test_an_admin_sees_the_admin_button():
    html = page("admin", **schedules_ctx())
    assert "value=\"approve\"" in html
