"""
measure.py
~~~~~~~~~~
Load-test measurements. Runs in the FleetWright image on the compose network
(see README.md):

    python /load/measure.py pages [repeats]
        times the main pages, signed in as the seeded admin
    python /load/measure.py run scan|apply agents|ssh|both [batch size]
        starts a run over the load-test hosts and times it to the end
"""

from __future__ import annotations

import asyncio
import http.cookiejar
import os
import re
import ssl
import statistics
import sys
import time
import urllib.parse
import urllib.request

sys.path[:0] = ["/app", "/load"]
from fleetwright import db, fleet  # noqa: E402
from seed import ADMIN  # noqa: E402

BASE = os.environ.get("FW_BASE", "https://web:8443")
CTX = ssl.create_default_context()
CTX.check_hostname = False
CTX.verify_mode = ssl.CERT_NONE


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k):
        return None


def browser():
    jar = http.cookiejar.CookieJar()
    return urllib.request.build_opener(urllib.request.HTTPSHandler(context=CTX),
                                       urllib.request.HTTPCookieProcessor(jar), _NoRedirect())


def get(opener, path: str) -> tuple[float, int, bytes]:
    t0 = time.perf_counter()
    try:
        with opener.open(BASE + path, timeout=300) as r:
            body, code = r.read(), r.status
    except urllib.error.HTTPError as e:
        body, code = e.read(), e.code
    return (time.perf_counter() - t0) * 1000, code, body


def sign_in(opener) -> None:
    _, _, body = get(opener, "/login")
    csrf = re.search(rb'name="csrf" value="([^"]+)"', body).group(1).decode()
    data = urllib.parse.urlencode({"csrf": csrf, "email": ADMIN[0], "password": ADMIN[1]}).encode()
    try:
        opener.open(urllib.request.Request(BASE + "/login", data=data), timeout=60)
    except urllib.error.HTTPError as e:
        if e.code != 303:
            raise


async def page_list() -> list[tuple[str, str]]:
    busiest = await db.fetchval("SELECT id FROM hosts ORDER BY pending_count DESC LIMIT 1")
    policy = await db.fetchval("SELECT id FROM policies WHERE name LIKE 'Load:%' LIMIT 1")
    big_run = await db.fetchval("SELECT run_id FROM tasks WHERE run_id IS NOT NULL GROUP BY run_id "
                                "ORDER BY COUNT(*) DESC LIMIT 1")
    pages = [("overview", "/"), ("hosts", "/hosts"), ("hosts 250/page", "/hosts?per=250"),
             ("hosts search pkg", "/hosts?q=pkg-0042"), ("hosts security", "/hosts?status=security"),
             ("host page (busiest)", f"/hosts/{busiest}"), ("policy page (preview)", f"/schedules/policies/{policy}"),
             ("schedules", "/schedules"), ("runs", "/runs")]
    if big_run:
        pages.append(("run page (biggest)", f"/runs/{big_run}"))
    return pages


async def pages(repeats: int) -> None:
    opener = browser()
    sign_in(opener)
    hosts = await db.fetchval("SELECT COUNT(*) FROM hosts")
    pend = await db.fetchval("SELECT COUNT(*) FROM pending_updates")
    print(f"{hosts} hosts, {pend} pending update rows; {repeats} requests per page\n")
    print(f"{'page':<24}{'median ms':>10}{'p95 ms':>9}{'max ms':>9}{'KB':>7}  status")
    for label, path in await page_list():
        get(opener, path)  # warm-up
        times, codes, size = [], set(), 0
        for _ in range(repeats):
            ms, code, body = get(opener, path)
            times.append(ms)
            codes.add(code)
            size = len(body)
        times.sort()
        p95 = times[min(len(times) - 1, int(len(times) * 0.95))]
        print(f"{label:<24}{statistics.median(times):>10.0f}{p95:>9.0f}{times[-1]:>9.0f}{size / 1024:>7.0f}  "
              f"{','.join(map(str, sorted(codes)))}")


async def run(op: str, which: str, batch: int) -> None:
    like = {"agents": ["load-agent-%"], "ssh": ["load-ssh-%"], "both": ["load-agent-%", "load-ssh-%"]}[which]
    ids = [r["id"] for r in await db.fetch("SELECT id FROM hosts WHERE name LIKE ANY(%s)", like)]
    sel = {"mode": "all"} if op == "apply" else None
    t0 = time.monotonic()
    run_id = await fleet.create_run(kind=op, title=f"Load test: {op} {which}", actor="load test",
                                    host_ids=ids, selection=sel, batch_size=batch)
    created = time.monotonic() - t0
    print(f"run #{run_id}: {op} on {len(ids)} hosts, batch {batch or 'all'} (created in {created * 1000:.0f} ms)")
    last = ""
    while True:
        await asyncio.sleep(2)
        status = await db.fetchval("SELECT status FROM runs WHERE id = %s", run_id)
        counts = {r["status"]: r["n"] for r in await db.fetch(
            "SELECT status, COUNT(*) AS n FROM tasks WHERE run_id = %s GROUP BY status", run_id)}
        line = " · ".join(f"{k} {v}" for k, v in sorted(counts.items()))
        if line != last:
            print(f"  {time.monotonic() - t0:6.0f} s  {line}", flush=True)
            last = line
        if status not in ("running", "paused"):
            break
    took = time.monotonic() - t0
    lag = await db.fetchone("""SELECT MAX(EXTRACT(EPOCH FROM finished_at - started_at)) AS slowest
                                 FROM tasks WHERE run_id = %s AND started_at IS NOT NULL""", run_id)
    failed = await db.fetch("SELECT detail, COUNT(*) AS n FROM tasks WHERE run_id = %s AND status = 'failed' "
                            "GROUP BY detail ORDER BY n DESC LIMIT 5", run_id)
    print(f"run #{run_id} {status} in {took:.0f} s ({len(ids) / took:.1f} hosts/s); "
          f"slowest task {float(lag['slowest'] or 0):.0f} s")
    for f in failed:
        print(f"  failed ×{f['n']}: {(f['detail'] or '')[:150]}")


async def main(argv: list[str]) -> None:
    await db.open_pool()
    if argv[:1] == ["pages"]:
        await pages(int(argv[1]) if len(argv) > 1 else 10)
    elif argv[:1] == ["run"]:
        await run(argv[1], argv[2], int(argv[3]) if len(argv) > 3 else 0)
    else:
        print(__doc__)
    await db.close_pool()


if __name__ == "__main__":
    asyncio.run(main(sys.argv[1:]))
