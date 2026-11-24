"""
check_preview.py
~~~~~~~~~~~~~~~~
The policy preview counts in SQL (views/schedules.selection_sql); installs pick
with pkgops.select. This checks they agree, on a load-test database: it varies
the data first (held lists, severities, enhancements, new packages), then
compares both for a range of selections. Changes the data: load-test databases only.

    python /load/check_preview.py
"""

from __future__ import annotations

import asyncio
import sys
import time

sys.path[:0] = ["/app", "/load"]
from fleetwright import db, fleet  # noqa: E402
from fleetwright.actions.schedules import _preview_python  # noqa: E402
from fleetwright.actions.schedules import compute_preview as preview  # noqa: E402

SELECTIONS = [
    {"mode": "all"},
    {"mode": "all", "exclude": ["pkg-00*", "openssl"]},
    {"mode": "kinds", "kinds": ["security"]},
    {"mode": "kinds", "kinds": ["security"], "min_severity": "important"},
    {"mode": "kinds", "kinds": ["security"], "min_severity": "critical", "exclude": ["libssl*"]},
    {"mode": "kinds", "kinds": ["kernel"]},
    {"mode": "kinds", "kinds": ["bugfix"]},
    {"mode": "kinds", "kinds": ["enhancement"]},
    {"mode": "kinds", "kinds": ["bugfix", "enhancement", "kernel"], "include": ["pkg-01?5", "pkg-02[0-4]*"]},
    {"mode": "kinds", "kinds": [], "include": ["pkg-0[!0-8]*", "open*"]},
    {"mode": "kinds", "kinds": ["security", "kernel"], "min_severity": "moderate", "exclude": ["linux-image-*"]},
]


async def vary() -> None:
    await db.execute("UPDATE hosts SET held = '{pkg-01*,openssh-server}' WHERE id % 7 = 0")
    await db.execute("UPDATE hosts SET held = '{linux-*}' WHERE id % 11 = 0")
    await db.execute("""UPDATE pending_updates
                           SET severity = (ARRAY['low','moderate','important','critical','odd'])
                                          [1 + abs(hashtext(name || host_id)) % 5]
                         WHERE is_security AND abs(hashtext(name || host_id)) % 3 = 0""")
    await db.execute("""UPDATE pending_updates SET kind = 'enhancement'
                         WHERE NOT is_security AND abs(hashtext(name || host_id)) % 5 = 0""")
    await db.execute("UPDATE pending_updates SET current = NULL WHERE abs(hashtext(name || host_id)) % 97 = 0")


async def main() -> int:
    await db.open_pool()
    await vary()
    ids = await fleet.resolve_target({"all": True})
    already = await db.fetchval("SELECT COUNT(*) FROM hosts WHERE reboot_required")
    bad = 0
    for sel in SELECTIONS:
        t0 = time.perf_counter()
        old = await _preview_python(ids, sel)
        t1 = time.perf_counter()
        pv = await preview({"all": True}, sel)
        t2 = time.perf_counter()
        new = (pv["updates"], pv["affected"], pv["reboot_hosts"] - already)
        bad += old != new
        print(f"{'OK ' if old == new else 'BAD'} python {old} {1000 * (t1 - t0):5.0f} ms | "
              f"sql {new} {1000 * (t2 - t1):4.0f} ms | {sel}")
    print("all match" if not bad else f"{bad} MISMATCHES")
    await db.close_pool()
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
