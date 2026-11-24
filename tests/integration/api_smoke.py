"""
api_smoke.py
~~~~~~~~~~~~
Drives a running FleetWright through its API, end to end, and checks the answers.
Needs an admin API token and some SSH hosts that answer (the load test's SSH farm
is ideal: tests/load/README.md). Changes the data: test installs only.

    python api_smoke.py https://fleetwright:8443 fwt_… [ssh key id]

Prints one line per check and exits non-zero if any fails.
"""

from __future__ import annotations

import json
import ssl
import sys
import time
import urllib.error
import urllib.request
import uuid
from datetime import datetime, timedelta, timezone

BASE, ADMIN = sys.argv[1].rstrip("/") + "/api/v1", sys.argv[2]
CTX = ssl.create_default_context()
CTX.check_hostname, CTX.verify_mode = False, ssl.CERT_NONE
failures = 0


def call(method, path, body=None, token=ADMIN, headers=None, raw=False):
    req = urllib.request.Request(BASE + path, method=method,
                                 data=json.dumps(body).encode() if body is not None else None,
                                 headers={"Content-Type": "application/json", **(headers or {}),
                                          **({"Authorization": f"Bearer {token}"} if token else {})})
    try:
        with urllib.request.urlopen(req, timeout=60, context=CTX) as r:
            data = r.read()
            return r.status, (data if raw else json.loads(data or b"null")), dict(r.headers)
    except urllib.error.HTTPError as e:
        data = e.read()
        try:
            return e.code, json.loads(data), dict(e.headers)
        except ValueError:
            return e.code, data.decode(errors="replace"), dict(e.headers)


def check(what, cond, detail=""):
    global failures
    failures += not cond
    print(f"{'ok  ' if cond else 'FAIL'} {what}" + (f"  ({detail})" if detail and not cond else ""), flush=True)


def wait_run(run_id, token=ADMIN, timeout=180):
    for _ in range(timeout):
        _, r, _ = call("GET", f"/runs/{run_id}", token=token)
        if r["status"] not in ("running", "paused"):
            return r
        time.sleep(1)
    return r


# ─── Tokens and roles ───────────────────────────────────────────────────────
s, me, _ = call("GET", "/me")
check("admin token works: GET /me", s == 200 and me["role"] == "admin", me)
s, body, h = call("GET", "/me", token=None)
check("no token: 401 with WWW-Authenticate", s == 401 and body["error"]["code"] == "unauthorized"
      and "Bearer" in h.get("www-authenticate", h.get("WWW-Authenticate", "")), body)
s, body, _ = call("GET", "/me", token="fwt_notarealtoken")
check("wrong token: 401", s == 401, body)
suffix = uuid.uuid4().hex[:6]
s, viewer, _ = call("POST", "/tokens", {"name": f"dashboard-{suffix}", "role": "viewer", "expires_days": 1})
check("admin makes a viewer token", s == 201 and viewer["token"].startswith("fwt_") and viewer["role"] == "viewer",
      viewer)
s, operator, _ = call("POST", "/tokens", {"name": f"ci-{suffix}", "role": "operator"})
check("admin makes an operator token", s == 201, operator)
s, body, _ = call("POST", "/tokens", {"name": f"sneaky-{suffix}", "role": "admin"}, token=viewer["token"])
check("a viewer token can't make an admin token", s == 403 and body["error"]["code"] == "forbidden", body)
s, body, _ = call("GET", "/users", token=viewer["token"])
check("viewer token: GET /users refused (admin only)", s == 403, body)
s, body, _ = call("POST", "/hosts/scan", {}, token=viewer["token"])
check("viewer token: starting a scan refused (operator)", s == 403 and "Operator" in body["error"]["message"], body)
s, body, _ = call("GET", "/tokens")
check("GET /tokens lists mine with last use", s == 200 and any(t["name"] == f"ci-{suffix}" for t in body["tokens"]))

# ─── Hosts ──────────────────────────────────────────────────────────────────
s, keys, _ = call("GET", "/ssh-keys")
key_id = int(sys.argv[3]) if len(sys.argv) > 3 else keys["keys"][0]["id"]
s, g, _ = call("POST", "/groups", {"name": f"api-{suffix}", "description": "made by api_smoke"})
check("POST /groups", s == 201, g)
gid = g["group_id"]
s, body, _ = call("POST", "/groups", {"name": f"api-{suffix}"})
check("duplicate group: 400 invalid", s == 400 and body["error"]["code"] == "invalid", body)
s, body, _ = call("GET", "/hosts?status=all&limit=1000", token=viewer["token"])
check("viewer token: GET /hosts", s == 200 and "counts" in body, body)
ssh_hosts = [h for h in body["hosts"] if h["mode"] == "ssh" and not h["last_error"]][:4]
check("there are SSH hosts to work with", len(ssh_hosts) >= 2, len(ssh_hosts))
ids = [h["id"] for h in ssh_hosts]
s, body, _ = call("POST", "/hosts/move", {"host_ids": ids, "group_id": gid}, token=operator["token"])
check("operator token: move hosts to the group", s == 200 and body["hosts"] == len(ids), body)
s, body, _ = call("POST", "/hosts/tag", {"host_ids": ids, "tags": ["api-test"]}, token=operator["token"])
check("operator token: tag hosts", s == 200, body)
s, body, _ = call("GET", f"/hosts?group={gid}&tag=api-test&limit=2")
check("filters and cursor paging: 2 at a time", s == 200 and len(body["hosts"]) == 2 and body["next_cursor"], body)
s, page2, _ = call("GET", f"/hosts?group={gid}&tag=api-test&limit=2&cursor={body['next_cursor']}")
check("next page continues after the cursor", s == 200 and all(h["id"] > body["next_cursor"] for h in page2["hosts"]))
s, one, _ = call("GET", f"/hosts/{ids[0]}")
check("GET /hosts/{id}, no token hash in it", s == 200 and "agent_token_hash" not in one and one["group_id"] == gid)
s, upd, _ = call("GET", f"/hosts/{ids[0]}/updates?kind=security")
check("GET /hosts/{id}/updates", s == 200 and "counts" in upd, upd)
s, body, _ = call("PATCH", f"/hosts/{ids[0]}", {"held": ["pkg-00*"]}, token=operator["token"])
check("PATCH a host's never-install list; other fields kept", s == 200 and body["held"] == ["pkg-00*"]
      and body["group_id"] == gid, body)
s, body, _ = call("GET", "/hosts/999999")
check("missing host: 404 not_found", s == 404 and body["error"]["code"] == "not_found", body)
s, body, _ = call("PATCH", f"/hosts/{ids[0]}", {"colour": "blue"}, token=operator["token"])
check("unknown field: 400 with the field named", s == 400 and "colour" in body["error"]["message"], body)

# ─── Runs ───────────────────────────────────────────────────────────────────
key = str(uuid.uuid4())
run_body = {"kind": "apply", "target": {"hosts": ids}, "selection": {"mode": "kinds", "kinds": ["security"]},
            "batch_size": 1, "canary": True, "max_failures": 1, "title": f"API security run {suffix}"}
s, r1, _ = call("POST", "/runs", run_body, token=operator["token"], headers={"Idempotency-Key": key})
check("operator token: POST /runs returns a run id at once", s == 201 and r1.get("run_id"), r1)
s, r2, h2 = call("POST", "/runs", run_body, token=operator["token"], headers={"Idempotency-Key": key})
check("same Idempotency-Key: same run, not a second one", s == 200 and r2 == r1
      and (h2.get("idempotent-replayed") or h2.get("Idempotent-Replayed")) == "true", (s, r2))
s, body, _ = call("POST", "/runs/1/retry", {}, token=operator["token"], headers={"Idempotency-Key": key})
check("that key on a different request: 409", s == 409 and body["error"]["code"] == "conflict", body)
run_id = r1["run_id"]
# Follow it as Server-Sent Events.
req = urllib.request.Request(f"{BASE}/runs/{run_id}/events", headers={"Authorization": f"Bearer {viewer['token']}"})
events, logs = [], 0
with urllib.request.urlopen(req, timeout=300, context=CTX) as stream:
    for line in stream:
        line = line.decode().rstrip("\n")
        if line.startswith("event: "):
            events.append(line[7:])
            if line == "event: end":
                break
        if line.startswith("data: ") and events and events[-1] == "log":
            logs += 1
check("SSE: run, task and log events, then end", events[:1] == ["run"] and "task" in events and logs > 0
      and events[-1] == "end", events[:8] + ["…"] + events[-3:])
r = wait_run(run_id)
check("the run finished with every host done", r["status"] == "done" and all(t["status"] == "done" for t in r["tasks"]),
      [(t["host"], t["status"], t["detail"]) for t in r["tasks"]])
check("canary first, one host per batch", r["batches"][0]["hosts"] == 1 and len(r["batches"]) == len(ids),
      r["batches"])
s, task, _ = call("GET", f"/tasks/{r['tasks'][0]['id']}")
check("GET /tasks/{id}: log and changes", s == 200 and "▸ apply" in task["log"] or "nothing to install" in task["log"],
      task.get("detail"))
s, hist, _ = call("GET", f"/hosts/{ids[0]}/history?limit=5")
check("host history shows the changes", s == 200 and isinstance(hist["changes"], list), hist)
s, body, _ = call("POST", f"/runs/{run_id}/pause", {}, token=operator["token"])
check("pausing a finished run: 400 with why", s == 400 and "not running" in body["error"]["message"], body)
s, slow, _ = call("POST", "/runs", {"kind": "scan", "target": {"hosts": ids}, "batch_size": 1}, token=operator["token"])
s, body, _ = call("POST", f"/runs/{slow['run_id']}/abort", {}, token=operator["token"])
check("abort a run", s == 200 and body["status"] == "aborted", body)

# ─── Policies and bookings ──────────────────────────────────────────────────
pol = {"name": f"API nightly {suffix}", "enabled": False, "target": {"groups": [gid]},
       "selection": {"mode": "kinds", "kinds": ["security", "kernel"], "exclude": ["openssh*"]},
       "repeat": "weekly", "weekdays": [5], "at_time": "03:15", "batch_percent": 50, "canary": True}
s, body, _ = call("POST", "/policies/preview", {"target": pol["target"], "selection": pol["selection"]},
                  token=viewer["token"])
check("viewer token: policy preview", s == 200 and body["hosts"] == len(ids), body)
s, body, _ = call("POST", "/policies", dict(pol, repeat="weekly", weekdays=[]), token=operator["token"])
check("invalid policy: every problem listed", s == 400 and "day of the week" in body["error"]["message"], body)
s, p, _ = call("POST", "/policies", pol, token=operator["token"])
check("create a policy", s == 201 and p["policy_id"], p)
s, body, _ = call("POST", f"/policies/{p['policy_id']}/enable", {}, token=operator["token"])
check("switch it on", s == 200 and body["enabled"] is True, body)
s, got, _ = call("GET", f"/policies/{p['policy_id']}")
check("GET it: schedule text, preview", s == 200 and got["schedule"].startswith("Sat 03:15") and "preview" in got,
      got)
s, run, _ = call("POST", f"/policies/{p['policy_id']}/run", {}, token=operator["token"],
                 headers={"Idempotency-Key": str(uuid.uuid4())})
check("run it now", s == 201 and run["run_id"], run)
wait_run(run["run_id"])
s, body, _ = call("DELETE", f"/policies/{p['policy_id']}", token=operator["token"])
check("delete it", s == 200, body)
start = datetime.now(timezone.utc) + timedelta(days=2)
s, upd, _ = call("GET", f"/hosts/{ids[1]}/updates")
pick = upd["updates"][0]["name"]
s, b, _ = call("POST", "/bookings", {"target": {"hosts": ids[1:2]}, "picked": {str(ids[1]): [{"name": pick}]},
                                     "window_start": start.isoformat(), "window_end": (start + timedelta(hours=1)).isoformat(),
                                     "needs_approval": True}, token=operator["token"])
check("book a picked update, needing approval", s == 201 and b["needs_approval"], b)
s, body, _ = call("POST", "/bookings", {"target": {"hosts": ids[1:2]}, "picked": {str(ids[1]): [{"name": "nope"}]},
                                        "window_start": start.isoformat(),
                                        "window_end": (start - timedelta(hours=1)).isoformat()},
                  token=operator["token"])
check("bad booking: both problems listed", s == 400 and len(body["error"]["errors"]) >= 2, body)
if b.get("booking_id"):
    s, body, _ = call("POST", f"/bookings/{b['booking_id']}/approve", {}, token=operator["token"])
    check("operator can't approve (admin)", s == 403, body)
    s, body, _ = call("POST", f"/bookings/{b['booking_id']}/approve", {})
    check("admin approves", s == 200 and body["status"] == "booked", body)
    s, body, _ = call("POST", f"/bookings/{b['booking_id']}/cancel", {}, token=operator["token"])
    check("operator cancels", s == 200, body)

# ─── Admin ──────────────────────────────────────────────────────────────────
for path in ("/overview", "/agents", "/notifications", "/backups", "/https", "/users", "/audit?limit=5",
             "/bookings", "/policies", "/runs?limit=3", "/groups"):
    s, body, _ = call("GET", path)
    check(f"GET {path}", s == 200, body)
s, body, _ = call("GET", "/audit?limit=20")
check("the audit log names the token", any(f"(token ci-{suffix})" in e["actor"] for e in body["entries"]),
      [e["actor"] for e in body["entries"][:5]])
s, u, _ = call("POST", "/users", {"email": f"api-{suffix}@example.com", "name": "API Person", "role": "viewer"})
check("add a user: setup link returned once", s == 201 and "/welcome/" in u["setup_link"], u)
s, body, _ = call("DELETE", f"/users/{u['user_id']}")
check("remove them", s == 200, body)
s, spec, _ = call("GET", "/openapi.json", token=None)
check("OpenAPI spec served without a token", s == 200 and spec["info"]["title"] == "FleetWright API")

# ─── Rate limit, then tidy up ───────────────────────────────────────────────
codes = [call("GET", "/me", token=viewer["token"])[0] for _ in range(130)]
check("rate limit: 429 after the burst", 429 in codes, codes[-5:])
s, body, h = call("GET", "/me", token=viewer["token"])
check("429 says when to retry", s == 429 and (h.get("retry-after") or h.get("Retry-After")), (s, h))
call("POST", "/hosts/move", {"host_ids": ids, "group_id": None})
call("PATCH", f"/hosts/{ids[0]}", {"held": []})
call("DELETE", f"/groups/{gid}")
for t in (viewer, operator):
    call("DELETE", f"/tokens/{t['token_id']}")
s, body, _ = call("GET", "/me", token=operator["token"])
check("a revoked token stops working", s == 401, body)

print(f"\n{'all passed' if not failures else f'{failures} FAILED'}")
sys.exit(1 if failures else 0)
