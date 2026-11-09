"""When an auto-install policy next runs. All times are UTC."""

from __future__ import annotations

from datetime import date, datetime, time, timedelta, timezone

WEEKDAYS = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"]


def _at(d: date, t: time) -> datetime:
    return datetime.combine(d, t.replace(tzinfo=None), tzinfo=timezone.utc)


def next_run(repeat: str, at_time: time, after: datetime, weekdays=None, monthday=None) -> datetime:
    """The first scheduled start strictly after `after`."""
    after = after.astimezone(timezone.utc)
    day = after.date()
    for offset in range(0, 400):
        d = day + timedelta(days=offset)
        when = _at(d, at_time)
        if when <= after:
            continue
        if repeat == "daily":
            return when
        if repeat == "weekly" and d.weekday() in (weekdays or [0]):
            return when
        if repeat == "monthly" and d.day == (monthday or 1):
            return when
    raise ValueError(f"no next run for {repeat}")


def describe(policy: dict) -> str:
    t = policy["at_time"].strftime("%H:%M")
    hours = policy["window_minutes"] / 60
    window = f"{hours:g} h window" if hours >= 1 else f"{policy['window_minutes']} min window"
    if policy["repeat"] == "daily":
        when = f"Daily {t}"
    elif policy["repeat"] == "weekly":
        days = ", ".join(WEEKDAYS[d] for d in sorted(policy["weekdays"] or [0]))
        when = f"{days} {t}"
    else:
        md = policy["monthday"] or 1
        suffix = "th" if 11 <= md <= 13 else {1: "st", 2: "nd", 3: "rd"}.get(md % 10, "th")
        when = f"Monthly on the {md}{suffix}, {t}"
    return f"{when}, {window}"
