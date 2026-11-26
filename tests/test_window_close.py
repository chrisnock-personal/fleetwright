"""The window-close menu must say what FleetWright actually does."""

import asyncio
import re
from datetime import datetime, timedelta, timezone

from starlette.requests import Request

from fleetwright import db, fleet
from fleetwright.webcommon import templates


def _booking_form_html():
    request = Request({"type": "http", "method": "GET", "path": "/schedules/book",
                       "query_string": b"", "headers": []})
    return templates.env.get_template("book.html").render(
        request=request, csrf="", current_user=None, flashes=[], errors=[], hosts=[], groups=[],
        pins=None, pin_rows=[], kinds=[], severities=[],
        form={"what": "kinds", "kinds": ["security"], "window_start": "2026-11-27T22:00",
              "window_end": "2026-11-28T00:00", "on_window_close": "finish_started",
              "batch_size": "1", "reboot": "if_needed"})


def test_booking_form_does_not_offer_an_immediate_stop():
    html = _booking_form_html().lower()
    assert "stop at once" not in html
    select = re.search(r'<select id="on_window_close".*?</select>', html, re.S)
    assert select
    options = re.findall(r'<option value="([^"]+)"[^>]*>([^<]+)</option>', select.group())
    assert [value for value, _ in options] == list(fleet.WINDOW_CLOSE_OPTIONS)
    assert "stop" not in [value for value, _ in options]
    labels = dict(options)
    assert "finish hosts already started" in labels["finish_started"].lower()
    assert "no new" in labels["finish_started"].lower()
    assert "carry on until done" in labels["carry_on"].lower()
    # Stored bookings and API clients can still send 'stop', but it no longer claims to stop mid-install.
    assert "finish hosts already started" in fleet.WINDOW_CLOSE["stop"].lower()
    assert "stop at once" not in fleet.WINDOW_CLOSE["stop"].lower()


def test_stop_value_still_skips_new_hosts_like_finish_started(monkeypatch):
    calls = []
    state = {"value": "finish_started"}
    run = {"id": 7, "status": "running", "max_failures": 0, "booking_id": None,
           "window_end": datetime.now(timezone.utc) - timedelta(minutes=1)}

    async def fake_fetch(sql, *args):
        if "FROM runs WHERE status" in sql:
            return [dict(run, on_window_close=state["value"])]
        if "GROUP BY status" in sql:
            return [{"status": "running", "n": 1}, {"status": "waiting", "n": 2}]
        raise AssertionError(sql)

    async def fake_execute(sql, *args):
        calls.append((sql, args))
        return 0

    monkeypatch.setattr(db, "fetch", fake_fetch)
    monkeypatch.setattr(db, "execute", fake_execute)

    def advance(value):
        state["value"] = value
        calls.clear()
        asyncio.run(fleet.advance_runs())
        return list(calls)

    finish_calls = advance("finish_started")
    assert len(finish_calls) == 1
    assert "status = 'skipped'" in finish_calls[0][0]
    assert finish_calls[0][1] == ("maintenance window closed", 7)
    assert advance("stop") == finish_calls
    assert advance("carry_on") == []
