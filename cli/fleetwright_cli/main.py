"""
fw: FleetWright from the command line.

Every command goes through FleetWright's API with your token, so it can do
exactly what your token's role allows: no more. Add --json to any command for
machine-readable output (--jsonl for streams), and rely on the exit codes:

    0 ok   1 failed (or a host failed)   2 usage   3 not allowed   4 not found
"""

from __future__ import annotations

import argparse
import getpass
import json
import os
import re
import shutil
import sys
import time
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

from . import __version__
from .client import (FAILED, NOT_ALLOWED, NOT_FOUND, OK, USAGE, CLIError, Client, fingerprint_of, forget_token,
                     load_config, resolve_profile, save_config, server_certificate, store_token)


# ─── Output ─────────────────────────────────────────────────────────────────

class Out:
    def __init__(self, args):
        self.json = getattr(args, "json", False)
        self.jsonl = getattr(args, "jsonl", False)
        self.tty = sys.stdout.isatty()

    def data(self, obj: Any) -> None:
        print(json.dumps(obj, indent=None if self.jsonl else 2, default=str))

    def table(self, rows: list[dict], cols: list[tuple[str, str]], key: Optional[str] = None,
              whole: Any = None) -> None:
        """rows as a table; with --json the whole answer, with --jsonl one item per line."""
        if self.jsonl:
            for r in rows:
                print(json.dumps(r, default=str))
            return
        if self.json:
            self.data(whole if whole is not None else rows)
            return
        if not rows:
            print("(none)")
            return
        cells = [[_cell(r, c) for c, _ in cols] for r in rows]
        widths = [max(len(h), *(len(row[i]) for row in cells)) for i, (_, h) in enumerate(cols)]
        room = shutil.get_terminal_size((160, 20)).columns if self.tty else 10_000
        last = max(10, room - sum(widths[:-1]) - 2 * (len(cols) - 1))
        widths[-1] = min(widths[-1], last)
        print("  ".join(h.upper().ljust(w) for (_, h), w in zip(cols, widths)).rstrip())
        for row in cells:
            print("  ".join((v if len(v) <= w else v[:w - 1] + "…").ljust(w) for v, w in zip(row, widths)).rstrip())

    def fields(self, obj: dict, keys: list[tuple[str, str]]) -> None:
        if self.json or self.jsonl:
            self.data(obj)
            return
        w = max(len(label) for _, label in keys)
        for k, label in keys:
            print(f"{label.ljust(w)}  {_cell(obj, k)}")

    def say(self, text: str) -> None:
        """A human message: on stderr when the output is JSON, so stdout stays parseable."""
        print(text, file=sys.stderr if (self.json or self.jsonl) else sys.stdout)


def _cell(row: dict, key: str) -> str:
    v: Any = row
    for part in key.split("."):
        v = v.get(part) if isinstance(v, dict) else None
    if v is None or v == "":
        return "-"
    if isinstance(v, bool):
        return "yes" if v else "no"
    if isinstance(v, list):
        return ", ".join(str(x) for x in v) or "-"
    if isinstance(v, str) and re.match(r"\d{4}-\d\d-\d\dT\d\d:\d\d", v):
        return v[:16].replace("T", " ")
    return str(v)


# ─── Parsing helpers ────────────────────────────────────────────────────────

def parse_since(text: str) -> datetime:
    """'7d', '12h', '30m', '2w', or a date/time."""
    m = re.fullmatch(r"(\d+)([mhdw])", text.strip())
    if m:
        n, unit = int(m.group(1)), m.group(2)
        return datetime.now(timezone.utc) - timedelta(**{{"m": "minutes", "h": "hours", "d": "days",
                                                          "w": "weeks"}[unit]: n})
    return _utc(datetime.fromisoformat(text))


def _utc(dt: datetime) -> datetime:
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def parse_window(text: str) -> tuple[datetime, datetime]:
    """'2026-11-12 22:00/23:30' (UTC): an end without a date is the same day, or the next if
    it's earlier than the start. Both ends may be full date-times, with an offset."""
    if "/" not in text:
        raise CLIError("A window looks like '2026-11-12 22:00/23:30'", USAGE)
    a, b = (s.strip() for s in text.split("/", 1))
    try:
        start = _utc(datetime.fromisoformat(a))
        if re.fullmatch(r"\d{1,2}:\d\d", b):
            hh, mm = map(int, b.split(":"))
            end = start.replace(hour=hh, minute=mm, second=0, microsecond=0)
            if end <= start:
                end += timedelta(days=1)
        else:
            end = _utc(datetime.fromisoformat(b))
    except ValueError as e:
        raise CLIError(f"Can't read the window '{text}': {e}", USAGE) from e
    return start, end


def parse_batch(text: Optional[str]) -> tuple[int, int]:
    """'10' hosts at a time, or '10%'. Returns (batch_size, batch_percent)."""
    if not text:
        return 0, 0
    m = re.fullmatch(r"(\d+)(%?)", text.strip())
    if not m:
        raise CLIError("--batch is a number of hosts, or a percentage like 10%", USAGE)
    n = int(m.group(1))
    return (0, min(100, n)) if m.group(2) else (n, 0)


def words(values: Optional[list[str]]) -> list[str]:
    """--tag a,b --tag c -> [a, b, c]"""
    out = []
    for v in values or []:
        out += [w.strip() for w in v.split(",") if w.strip()]
    return out


# ─── Names to ids ───────────────────────────────────────────────────────────

class Resolver:
    def __init__(self, api: Client):
        self.api = api
        self._hosts: Optional[dict] = None

    def hosts(self, refs: list[str]) -> list[int]:
        ids, names = [], []
        for r in refs:
            (ids if r.isdigit() else names).append(r)
        out = [int(i) for i in ids]
        if names:
            if self._hosts is None:
                self._hosts = {h["name"]: h["id"] for h in self.api.pages("/hosts", "hosts", limit=1000)}
            missing = [n for n in names if n not in self._hosts]
            if missing:
                raise CLIError(f"No such host: {', '.join(missing)}", NOT_FOUND)
            out += [self._hosts[n] for n in names]
        return out

    def host(self, ref: str) -> int:
        return self.hosts([ref])[0]

    def _named(self, path: str, key: str, what: str, ref: str) -> int:
        if ref.isdigit():
            return int(ref)
        for item in self.api.get(path)[key]:
            if item["name"] == ref:
                return item["id"]
        raise CLIError(f"No such {what}: {ref}", NOT_FOUND)

    def group(self, ref: Optional[str]) -> Optional[int]:
        if ref in (None, "", "none"):
            return None
        return self._named("/groups", "groups", "group", ref)

    def groups(self, refs: list[str]) -> list[int]:
        return [self.group(r) for r in refs]

    def key(self, ref: str) -> int:
        return self._named("/ssh-keys", "keys", "SSH key", ref)


def target_from(args, rs: Resolver) -> dict:
    t = {"all": bool(getattr(args, "all_hosts", False)), "hosts": rs.hosts(getattr(args, "hosts", None) or []),
         "groups": rs.groups(words(getattr(args, "group", None))), "tags": words(getattr(args, "tag", None)),
         "exclude_tags": words(getattr(args, "exclude_tag", None))}
    if not (t["all"] or t["hosts"] or t["groups"] or t["tags"]):
        raise CLIError("Say which hosts: name them, or use --group, --tag or --all.", USAGE)
    return t


def selection_from(args) -> dict:
    exclude = words(getattr(args, "exclude", None))
    kinds = words(getattr(args, "kinds", None))
    include = words(getattr(args, "include", None))
    if kinds or include or getattr(args, "min_severity", None):
        sel = {"mode": "kinds", "kinds": kinds, "include": include}
        if args.min_severity:
            sel["min_severity"] = args.min_severity
    else:
        sel = {"mode": "all"}
    sel["exclude"] = exclude
    return sel


def confirm(args, question: str) -> None:
    if getattr(args, "yes", False):
        return
    if not sys.stdin.isatty():
        raise CLIError(f"{question} Add --yes to go ahead without a prompt.", USAGE)
    if input(f"{question} [y/N] ").strip().lower() not in ("y", "yes"):
        raise CLIError("Cancelled.", USAGE)


# ─── Commands ───────────────────────────────────────────────────────────────

def cmd_login(args, out: Out):
    cfg = load_config()
    name = args.profile or os.environ.get("FW_PROFILE") or cfg.get("default") or "default"
    old = cfg["profiles"].get(name, {})
    url = (args.url or old.get("url") or "").rstrip("/")
    if not url:
        raise CLIError("Give the server: fw login --url https://fleetwright:8443", USAGE)
    fingerprint = None
    if url.startswith("https://"):
        der, trusted = server_certificate(url)
        fp = fingerprint_of(der)
        if args.fingerprint:
            if args.fingerprint.replace(":", "").upper() != fp.replace(":", ""):
                raise CLIError(f"The server's certificate is {fp}, not the fingerprint given. Nothing was sent.",
                               NOT_ALLOWED)
            fingerprint = fp
        elif not trusted:
            print(f"The server's certificate isn't signed by a CA this machine trusts.\n"
                  f"Its SHA-256 fingerprint:\n  {fp}\n"
                  f"Check it matches Settings → HTTPS in FleetWright (or pass --fingerprint).", file=sys.stderr)
            if not sys.stdin.isatty():
                raise CLIError("Not pinning a certificate without a check: pass --fingerprint.", USAGE)
            if input("Pin this certificate? [y/N] ").strip().lower() not in ("y", "yes"):
                raise CLIError("Not logged in.", USAGE)
            fingerprint = fp
    token = (sys.stdin.readline().strip() if args.token_stdin
             else os.environ.get("FW_TOKEN") or getpass.getpass("API token (from your Account page): ").strip())
    if not token:
        raise CLIError("No token given.", USAGE)
    me = Client(url, token, fingerprint).get("/me")
    cfg["profiles"][name] = {"url": url, **({"fingerprint": fingerprint} if fingerprint else {})}
    where = store_token(name, token, cfg)
    if not cfg.get("default") or args.default:
        cfg["default"] = name
    save_config(cfg)
    out.say(f"Logged in to {url} as {me['name']} ({me['role']}, token {me['token_name']}); profile '{name}', "
            f"token kept in {where}.")
    return OK


def cmd_logout(args, out: Out):
    cfg = load_config()
    name = args.profile or cfg.get("default")
    if name not in cfg["profiles"]:
        raise CLIError(f"No profile {name}", NOT_FOUND)
    forget_token(name, cfg)
    del cfg["profiles"][name]
    if cfg.get("default") == name:
        cfg["default"] = next(iter(cfg["profiles"]), None)
    save_config(cfg)
    out.say(f"Forgot profile {name}. The token still works until you revoke it in FleetWright.")
    return OK


def cmd_profiles(args, out: Out):
    cfg = load_config()
    rows = [{"name": n, "url": p["url"], "default": n == cfg.get("default"), "pinned": bool(p.get("fingerprint"))}
            for n, p in cfg["profiles"].items()]
    out.table(rows, [("name", "profile"), ("url", "server"), ("default", "default"), ("pinned", "pinned cert")])
    return OK


def cmd_whoami(args, out: Out, api: Client):
    out.fields(api.get("/me"), [("name", "name"), ("role", "role"), ("token_name", "token")])
    return OK


HOST_COLS = [("id", "id"), ("name", "name"), ("group_name", "group"), ("os_pretty", "os"),
             ("pending_count", "pending"), ("security_count", "security"), ("reboot_required", "reboot"),
             ("mode", "via"), ("last_scan_at", "scanned")]


def cmd_hosts_list(args, out: Out, api: Client):
    rs = Resolver(api)
    params = {"status": args.status, "group": "none" if args.group == "none" else (rs.group(args.group) or ""),
              "tag": args.tag or "", "os": args.os or "", "mode": args.mode or "", "q": args.search or ""}
    if args.limit:
        page = api.get("/hosts", limit=args.limit, **params)
        rows = page["hosts"]
    else:
        rows = list(api.pages("/hosts", "hosts", limit=1000, **params))
    out.table(rows, HOST_COLS, whole={"hosts": rows})
    return OK


def cmd_hosts_show(args, out: Out, api: Client):
    h = api.get(f"/hosts/{Resolver(api).host(args.host)}")
    out.fields(h, [("name", "name"), ("id", "id"), ("address", "address"), ("mode", "connection"),
                   ("os_pretty", "os"), ("kernel", "kernel"), ("group_name", "group"), ("tags", "tags"),
                   ("held", "never install"), ("pending_count", "pending"), ("security_count", "security"),
                   ("reboot_required", "reboot needed"), ("agent_version", "agent"), ("last_scan_at", "last scan"),
                   ("last_error", "last error")])
    return OK


def cmd_hosts_add(args, out: Out, api: Client):
    rs = Resolver(api)
    addr, _, port = args.address.partition(":")
    r = api.post("/hosts", {"hosts": [{"name": args.name, "address": addr, "port": int(port or 22)}],
                            "credential_id": rs.key(args.key), "group_id": rs.group(args.host_group),
                            "tags": words(args.tag)})
    if out.json:
        out.data(r)
    elif r["added"]:
        out.say(f"Added {args.name} (host {r['added'][0]}); scanning it now.")
    else:
        out.say(f"{args.name} was already known; left alone.")
    return OK


def cmd_hosts_edit(args, out: Out, api: Client):
    rs = Resolver(api)
    body: dict = {}
    for f in ("name", "address", "port"):
        if getattr(args, f) is not None:
            body[f] = getattr(args, f)
    if args.host_group is not None:
        body["group_id"] = rs.group(args.host_group)
    if args.tags is not None:
        body["tags"] = words([args.tags])
    if args.held is not None:
        body["held"] = words([args.held])
    if args.key is not None:
        body["credential_id"] = rs.key(args.key)
    if not body:
        raise CLIError("Nothing to change: give --name, --group, --tags, --held, --address, --port or --key.", USAGE)
    h = api.request("PATCH", f"/hosts/{rs.host(args.host)}", body)
    out.fields(h, [("name", "name"), ("group_id", "group id"), ("tags", "tags"), ("held", "never install"),
                   ("address", "address"), ("port", "port")])
    return OK


def cmd_hosts_remove(args, out: Out, api: Client):
    ids = Resolver(api).hosts(args.hosts)
    confirm(args, f"Remove {len(ids)} host{'s' if len(ids) != 1 else ''} and their history?")
    r = api.post("/hosts/delete", {"host_ids": ids})
    out.data(r) if out.json else out.say(f"Removed {', '.join(r['removed'])}.")
    return OK


def cmd_hosts_scan(args, out: Out, api: Client):
    if not args.hosts and not args.all_hosts:
        raise CLIError("Name the hosts to scan, or --all.", USAGE)
    ids = None if args.all_hosts else Resolver(api).hosts(args.hosts)
    r = api.post("/hosts/scan", {"host_ids": ids})
    out.data(r) if out.json else out.say(f"Scanning {r['queued']} host{'s' if r['queued'] != 1 else ''}.")
    return OK


def cmd_hosts_tag(args, out: Out, api: Client):
    r = api.post("/hosts/tag", {"host_ids": Resolver(api).hosts(args.hosts), "tags": words(args.tags)})
    out.data(r) if out.json else out.say(f"Tagged {r['hosts']} hosts.")
    return OK


def cmd_hosts_move(args, out: Out, api: Client):
    rs = Resolver(api)
    r = api.post("/hosts/move", {"host_ids": rs.hosts(args.hosts), "group_id": rs.group(args.to)})
    out.data(r) if out.json else out.say(f"Moved {r['hosts']} hosts.")
    return OK


def cmd_hosts_forget_key(args, out: Out, api: Client):
    r = api.post(f"/hosts/{Resolver(api).host(args.host)}/forget-host-key")
    out.data(r) if out.json else out.say("Cleared: the next connection pins whatever key the host offers.")
    return OK


def cmd_updates(args, out: Out, api: Client):
    r = api.get(f"/hosts/{Resolver(api).host(args.host)}/updates", kind=args.kind)
    out.table(r["updates"], [("name", "package"), ("current", "installed"), ("available", "available"),
                             ("kind", "kind"), ("severity", "severity"), ("is_kernel", "kernel"), ("held", "held"),
                             ("advisory", "advisory")], whole=r)
    return OK


def cmd_history(args, out: Out, api: Client):
    hid = Resolver(api).host(args.host)
    since = parse_since(args.since).isoformat() if args.since else None
    r = api.get(f"/hosts/{hid}/history", since=since, limit=args.limit)
    out.table(r["changes"], [("at", "when"), ("name", "package"), ("from_version", "from"),
                             ("to_version", "to")], whole=r)
    return OK


# Runs

RUN_COLS = [("id", "run"), ("title", "title"), ("kind", "kind"), ("status", "status"), ("total", "hosts"),
            ("failed", "failed"), ("created_by", "by"), ("created_at", "started"), ("note", "note")]


def _finished(run: dict) -> bool:
    return run["status"] not in ("running", "paused")


def wait_for(api: Client, run_id: int, out: Out, follow: bool) -> int:
    """Until the run ends: the exit code is 0 only if every host succeeded."""
    if follow:
        return watch(api, run_id, out)
    while True:
        run = api.get(f"/runs/{run_id}")
        if _finished(run):
            break
        time.sleep(3)
    return report_run(run, out)


def report_run(run: dict, out: Out) -> int:
    failed = [t for t in run["tasks"] if t["status"] == "failed"]
    ok = run["status"] == "done" and not failed
    if out.json:
        out.data(run)
    else:
        out.say(f"Run #{run['id']} {run['status']}{': ' + run['note'] if run.get('note') else ''} "
                f"({sum(t['status'] == 'done' for t in run['tasks'])} done, {len(failed)} failed, "
                f"{run.get('packages_changed', 0)} packages changed)")
        for t in failed:
            out.say(f"  {t['host']}: {t['detail']}")
    return OK if ok else FAILED


def watch(api: Client, run_id: int, out: Out) -> int:
    for event, data in api.events(f"/runs/{run_id}/events"):
        if out.jsonl or out.json:
            print(json.dumps({"event": event, "data": data}, default=str), flush=True)
        elif event == "run":
            print(f"▸ run #{data['id']} {data['status']}", flush=True)
        elif event == "task":
            print(f"▸ {data['host']}: {data['status']}" + (f" ({data['detail']})" if data.get("detail") else ""),
                  flush=True)
        elif event == "log":
            for line in data["text"].splitlines():
                print(f"  {data['host']}  {line}", flush=True)
    run = api.get(f"/runs/{run_id}")
    if out.json or out.jsonl:
        return OK if run["status"] == "done" and not any(t["status"] == "failed" for t in run["tasks"]) else FAILED
    return report_run(run, out)


def cmd_run_start(args, out: Out, api: Client):
    rs = Resolver(api)
    kind = {"apply": "apply", "reboot": "reboot", "scan": "scan", "auto-off": "auto_off",
            "update-agents": "agent_update"}[args.run_kind]
    target = target_from(args, rs)
    body: dict = {"kind": kind, "target": target, "title": args.title or "", "canary": args.canary,
                  "max_failures": args.max_failures, "reboot": args.reboot.replace("-", "_")}
    body["batch_size"], body["batch_percent"] = parse_batch(args.batch)
    picked = words(getattr(args, "pick", None))
    if kind == "apply":
        if picked:
            body["picked"] = {str(h): [{"name": p} for p in picked] for h in target["hosts"]}
            if not target["hosts"] or target["groups"] or target["tags"] or target["all"]:
                raise CLIError("--pick needs the hosts named, not a group or tag.", USAGE)
        else:
            body["selection"] = selection_from(args)
    if args.dry_run:
        return dry_run(api, out, kind, body, picked)
    count = len(target["hosts"]) if target["hosts"] and not (target["groups"] or target["tags"] or target["all"]) \
        else None
    what = {"apply": "Install updates on", "reboot": "Reboot", "scan": "Scan", "auto_off":
            "Turn off the automatic updates of", "agent_update": "Update the agents of"}[kind]
    confirm(args, f"{what} {f'{count} host' + ('s' if count != 1 else '') if count else 'the matching hosts'}?")
    key = args.idempotency_key or str(uuid.uuid4())
    r = api.post("/runs", body, headers={"Idempotency-Key": key})
    if not args.wait:
        out.data(r) if out.json else out.say(f"Started run #{r['run_id']}. Follow it: fw run watch {r['run_id']}")
        return OK
    out.say(f"Started run #{r['run_id']}.")
    return wait_for(api, r["run_id"], out, follow=args.follow)


def dry_run(api: Client, out: Out, kind: str, body: dict, picked: list[str]) -> int:
    """What a run would do now, without starting it."""
    if kind != "apply":
        hosts = api.post("/policies/preview", {"target": body["target"], "selection": {"mode": "all"}})["hosts"]
        r = {"would": kind, "hosts": hosts}
        out.data(r) if out.json else out.say(f"Would {kind.replace('_', ' ')} {hosts} host{'s' if hosts != 1 else ''}.")
        return OK
    if picked:
        rows, missing = [], []
        for hid in body["target"]["hosts"]:
            pending = {u["name"]: u for u in api.get(f"/hosts/{hid}/updates")["updates"]}
            for name in picked:
                if name in pending:
                    rows.append({"host": hid, "package": name, "installed": pending[name]["current"],
                                 "would_install": pending[name]["available"]})
                else:
                    missing.append({"host": hid, "package": name})
        out.table(rows, [("host", "host"), ("package", "package"), ("installed", "installed"),
                         ("would_install", "would install")], whole={"would_install": rows, "not_pending": missing})
        if missing and not out.json:
            out.say("Not pending, so a run would refuse: "
                    + ", ".join(f"{m['package']} on host {m['host']}" for m in missing))
        return USAGE if missing else OK
    r = api.post("/policies/preview", {"target": body["target"], "selection": body["selection"]})
    if out.json:
        out.data(r)
    else:
        out.say(f"Would install {r['updates']} update{'s' if r['updates'] != 1 else ''} on {r['affected']} of "
                f"{r['hosts']} matching host{'s' if r['hosts'] != 1 else ''}; {r['reboot_hosts']} would likely "
                "need a reboot.")
    return OK


def cmd_runs_list(args, out: Out, api: Client):
    r = api.get("/runs", limit=args.limit, status=args.status or "")
    out.table(r["runs"], RUN_COLS, whole=r)
    return OK


def cmd_run_show(args, out: Out, api: Client):
    run = api.get(f"/runs/{args.run}")
    if out.json:
        out.data(run)
        return OK
    out.fields(run, [("id", "run"), ("title", "title"), ("kind", "kind"), ("status", "status"), ("note", "note"),
                     ("created_by", "started by"), ("created_at", "started"), ("finished_at", "finished"),
                     ("packages_changed", "packages changed")])
    print()
    out.table(run["tasks"], [("id", "task"), ("host", "host"), ("batch", "batch"), ("status", "status"),
                             ("changed", "changed"), ("detail", "detail")])
    return OK


def cmd_run_watch(args, out: Out, api: Client):
    return watch(api, args.run, out)


def cmd_run_control(args, out: Out, api: Client):
    action = args.run_action
    if action == "abort":
        confirm(args, f"Abort run #{args.run}?")
    r = api.post(f"/runs/{args.run}/{action}")
    if action == "retry" and args.wait:
        out.say(f"Started run #{r['run_id']} on the hosts that failed.")
        return wait_for(api, r["run_id"], out, follow=False)
    out.data(r) if out.json else out.say(
        f"Started run #{r['run_id']} on the hosts that failed." if action == "retry" else f"Run #{args.run}: {r['status']}.")
    return OK


def cmd_task(args, out: Out, api: Client):
    t = api.get(f"/tasks/{args.task}")
    if out.json:
        out.data(t)
    else:
        out.say(f"Task {t['id']} on {t['host']}: {t['status']}" + (f" ({t['detail']})" if t.get("detail") else ""))
        print(t["log"].rstrip())
    return OK


# Policies and bookings

def cmd_policies(args, out: Out, api: Client):
    a = args.policy_action
    if a == "list":
        r = api.get("/policies")
        out.table(r["policies"], [("id", "id"), ("name", "name"), ("enabled", "on"), ("schedule", "when"),
                                  ("target_text", "hosts"), ("next_run_at", "next run")], whole=r)
        return OK
    if a == "create":
        with open(args.file) as f:
            body = json.load(f)
        r = api.post("/policies", body)
        out.data(r) if out.json else out.say(f"Created policy #{r['policy_id']}.")
        return OK
    pid = args.policy
    if a == "show":
        p = api.get(f"/policies/{pid}")
        if out.json:
            out.data(p)
            return OK
        out.fields(p, [("name", "name"), ("enabled", "on"), ("schedule", "when"), ("selection.mode", "installs"),
                       ("selection.kinds", "kinds"), ("selection.min_severity", "min severity"),
                       ("selection.exclude", "never"), ("target.groups", "groups"), ("target.tags", "tags"),
                       ("target.all", "all hosts"), ("batch_size", "batch"), ("batch_percent", "batch %"),
                       ("canary", "canary"), ("max_failures", "stop after"), ("reboot", "reboot"),
                       ("next_run_at", "next run")])
        pv = p["preview"]
        print(f"\nNow it would install {pv['updates']} updates on {pv['affected']} of {pv['hosts']} hosts.")
        return OK
    if a in ("enable", "disable"):
        r = api.post(f"/policies/{pid}/{a}")
        out.data(r) if out.json else out.say(f"{r['name']} is {'on' if r['enabled'] else 'off'}.")
        return OK
    if a == "run":
        confirm(args, f"Run policy #{pid} now?")
        r = api.post(f"/policies/{pid}/run", headers={"Idempotency-Key": args.idempotency_key or str(uuid.uuid4())})
        if args.wait:
            out.say(f"Started run #{r['run_id']}.")
            return wait_for(api, r["run_id"], out, follow=False)
        out.data(r) if out.json else out.say(f"Started run #{r['run_id']}.")
        return OK
    if a == "delete":
        confirm(args, f"Delete policy #{pid}?")
        r = api.request("DELETE", f"/policies/{pid}")
        out.data(r) if out.json else out.say(f"Deleted {r['deleted']}.")
        return OK
    raise CLIError(f"Unknown: {a}", USAGE)


def cmd_book(args, out: Out, api: Client):
    rs = Resolver(api)
    start, end = parse_window(args.window)
    target = {"hosts": rs.hosts(args.hosts or []), "groups": rs.groups(words(args.group)), "tags": words(args.tag)}
    if not (target["hosts"] or target["groups"] or target["tags"]):
        raise CLIError("Say which hosts: name them, or use --group or --tag.", USAGE)
    body = {"target": target, "window_start": start.isoformat(), "window_end": end.isoformat(),
            "title": args.title or "", "reboot": args.reboot.replace("-", "_"), "batch_size": args.batch,
            "needs_approval": args.needs_approval, "on_window_close": args.on_close.replace("-", "_")}
    picked = words(args.pin)
    if picked:
        body["picked"] = {str(h): [{"name": p} for p in picked] for h in target["hosts"]}
    else:
        body["selection"] = selection_from(args)
    r = api.post("/bookings", body)
    if out.json:
        out.data(r)
    else:
        out.say(f"Booked #{r['booking_id']} for {start:%a %d %b %H:%M}–{end:%H:%M} UTC"
                + (": it needs an admin's approval first." if r["needs_approval"] else "."))
    return OK


def cmd_bookings(args, out: Out, api: Client):
    if args.booking_action == "list":
        r = api.get("/bookings")
        out.table(r["bookings"], [("id", "id"), ("title", "title"), ("status", "status"),
                                  ("window_start", "from"), ("window_end", "until"), ("created_by", "by"),
                                  ("target_text", "hosts")], whole=r)
        return OK
    r = api.post(f"/bookings/{args.booking}/{args.booking_action}")
    out.data(r) if out.json else out.say(f"Booking #{args.booking}: {r['status']}.")
    return OK


# Everything else

def cmd_overview(args, out: Out, api: Client):
    o = api.get("/overview")
    if out.json:
        out.data(o)
        return OK
    t, p = o["totals"], o["packages"]
    print(f"{t['hosts']} hosts ({t['agents']} agent, {t['ssh']} SSH): {t['with_updates']} with updates, "
          f"{t['with_security']} with security updates, {t['reboot']} need a reboot, {t['unreachable']} unreachable.")
    print(f"{p['pending']} updates pending, {p['advisories']} security advisories, "
          f"{p['critical_hosts']} hosts with a critical one.")
    if o["attention"]:
        print("\nNeeds attention:")
        for a in o["attention"]:
            print(f"  {a['badge']:<14} {a['name']}: {a['detail'].rstrip(' ·')}")
    return OK


def cmd_audit(args, out: Out, api: Client):
    r = api.get("/audit", limit=args.limit)
    out.table(r["entries"], [("at", "when"), ("actor", "who"), ("what", "what")], whole=r)
    return OK


def cmd_simple_list(path: str, key: str, cols: list[tuple[str, str]]):
    def run(args, out: Out, api: Client):
        r = api.get(path)
        out.table(r[key], cols, whole=r)
        return OK
    return run


def cmd_groups(args, out: Out, api: Client):
    a = args.group_action
    if a == "add":
        r = api.post("/groups", {"name": args.name, "description": args.description or ""})
        text = f"Added group {args.name} (id {r['group_id']})."
    elif a == "rename":
        r = api.request("PUT", f"/groups/{Resolver(api).group(args.group)}",
                        {"name": args.name, "description": args.description or ""})
        text = f"Renamed it {args.name}."
    else:
        confirm(args, f"Delete group {args.group}? Its hosts stay, ungrouped.")
        r = api.request("DELETE", f"/groups/{Resolver(api).group(args.group)}")
        text = f"Deleted group {r['deleted']}; its hosts are ungrouped."
    out.data(r) if out.json else out.say(text)
    return OK


def cmd_keys(args, out: Out, api: Client):
    if args.key_action == "add":
        private = open(args.private_key_file).read() if args.private_key_file else ""
        r = api.post("/ssh-keys", {"name": args.name, "username": args.user, "private_key": private})
        if out.json:
            out.data(r)
        else:
            out.say(f"Saved key {args.name}. Its public key, for ~{args.user}/.ssh/authorized_keys:")
            print(r["public_key"])
        return OK
    confirm(args, f"Delete SSH key {args.key}?")
    r = api.request("DELETE", f"/ssh-keys/{Resolver(api).key(args.key)}")
    out.data(r) if out.json else out.say(f"Deleted {r['deleted']}. Hosts that used it need another key.")
    return OK


def cmd_users(args, out: Out, api: Client):
    a = args.user_action
    if a == "add":
        r = api.post("/users", {"email": args.email, "name": args.name, "role": args.role})
        out.data(r) if out.json else out.say(f"Added {args.name}. Their setup link (once, 72 hours):\n{r['setup_link']}")
    elif a == "role":
        r = api.request("PATCH", f"/users/{args.user}", {"role": args.role})
        out.data(r) if out.json else out.say(f"User #{args.user} is now {r['role']}.")
    elif a == "link":
        r = api.post(f"/users/{args.user}/setup-link")
        out.data(r) if out.json else out.say(f"Setup link for {r['name']} (once, 72 hours):\n{r['setup_link']}")
    else:
        confirm(args, f"Remove user #{args.user}?")
        r = api.request("DELETE", f"/users/{args.user}")
        out.data(r) if out.json else out.say(f"Removed {r['deleted']}.")
    return OK


def cmd_tokens(args, out: Out, api: Client):
    a = args.token_action
    if a == "list":
        r = api.get("/tokens", everyone=str(args.everyone).lower())
        out.table(r["tokens"], [("id", "id"), ("name", "name"), ("owner", "owner"), ("role", "role"),
                                ("expires_at", "expires"), ("last_used_at", "last used"), ("revoked_at", "revoked")],
                  whole=r)
    elif a == "create":
        r = api.post("/tokens", {"name": args.name, "role": args.role, "expires_days": args.expires_days})
        out.data(r) if out.json else out.say(f"Token {r['name']} ({r['role']}), shown only now:\n{r['token']}")
    else:
        r = api.request("DELETE", f"/tokens/{args.token}")
        out.data(r) if out.json else out.say(f"Revoked {r['revoked']}.")
    return OK


def cmd_agents(args, out: Out, api: Client):
    if args.agent_action == "update":
        confirm(args, "Update every agent that differs from the server's (one host first, then 10% at a time)?")
        r = api.post("/agents/update", headers={"Idempotency-Key": str(uuid.uuid4())})
        if args.wait:
            return wait_for(api, r["run_id"], out, follow=False)
        out.data(r) if out.json else out.say(f"Started run #{r['run_id']}.")
        return OK
    r = api.get("/agents")
    if out.json:
        out.data(r)
        return OK
    a, s = r["agents"], r["server_agent"]
    print(f"{a['enrolled']} agents, {a['connected']} connected. The server hands out {s['version']} ({s['bundle']}); "
          f"{a['updatable']} could update to it, {a['too_old']} too old to update themselves.")
    return OK


def cmd_enrol(args, out: Out, api: Client):
    if args.enrol_action == "revoke":
        r = api.request("DELETE", f"/enrolment-tokens/{args.token}")
        out.data(r) if out.json else out.say("Revoked. Agents already enrolled with it keep working.")
        return OK
    rs = Resolver(api)
    r = api.post("/enrolment-tokens", {"label": args.label or "", "group_id": rs.group(args.host_group),
                                       "tags": words(args.tag), "uses": args.uses, "days": args.days})
    out.data(r) if out.json else out.say(f"Run this on each host (shown only now):\n{r['install_command']}")
    return OK


def cmd_notifications(args, out: Out, api: Client):
    if args.notify_action == "test":
        r = api.post(f"/notifications/channels/{args.channel}/test")
        if out.json:
            out.data(r)
        else:
            out.say("Sent." if r["sent"] else f"Failed: {r['error']}")
        return OK if r["sent"] else FAILED
    r = api.get("/notifications")
    out.table(r["channels"], [("id", "id"), ("name", "name"), ("kind", "kind"), ("enabled", "on"),
                              ("events", "events"), ("last_sent_at", "last sent"), ("last_error", "last error")],
              whole=r)
    return OK


def cmd_backups(args, out: Out, api: Client):
    r = api.get("/backups")
    if out.json:
        out.data(r)
        return OK
    b = r["backup"]
    if not b:
        print("No backups have been made.")
    else:
        print(f"Last backup {b['at']}: {'saved ' + b['file'] if b['ok'] else 'FAILED: ' + b['message']}"
              f"{' (overdue)' if b.get('overdue') else ''}; {b['kept']} kept, {b['schedule']}.")
    if r["secret_key"].get("problem"):
        print(r["secret_key"]["problem"])
    return OK if b and b["ok"] and not b.get("overdue") else FAILED


def cmd_https(args, out: Out, api: Client):
    r = api.get("/https")
    if out.json or not r.get("certificate"):
        out.data(r)
        return OK
    c = r["certificate"]
    out.fields(c, [("names", "names"), ("not_after", "expires"), ("self_signed", "self-signed"),
                   ("sha256", "fingerprint")])
    return OK


# ─── The command tree ───────────────────────────────────────────────────────

EXAMPLES = {
    "hosts": "fw hosts list --status security --group web\nfw hosts show web-07\n"
             "fw hosts add --key prod web-01 10.0.0.11\nfw hosts scan web-01 web-02",
    "run": "fw run apply --group web --kinds security --batch 10% --canary --reboot if-needed --dry-run\n"
           "fw run apply --group web --kinds security --batch 10% --canary --yes --wait\n"
           "fw run apply web-07 --pick openssl,curl --yes\nfw run watch 42\nfw run abort 42",
    "book": "fw book web-07 --window '2026-11-12 22:00/23:30' --pin openssl,curl\n"
            "fw book --group build --window '2026-11-14 23:00/02:00' --needs-approval --reboot always",
}


def add_target(p, hosts_positional=True):
    if hosts_positional:
        p.add_argument("hosts", nargs="*", metavar="HOST", help="host names or ids")
    p.add_argument("--group", action="append", help="a group (name or id); repeat or comma-separate")
    p.add_argument("--tag", action="append", help="hosts with a tag; repeat or comma-separate")
    p.add_argument("--all", dest="all_hosts", action="store_true", help="every host")
    p.add_argument("--exclude-tag", action="append", help="leave out hosts with this tag")


def add_selection(p):
    p.add_argument("--kinds", action="append", help="security, kernel, bugfix, enhancement (default: everything)")
    p.add_argument("--min-severity", choices=["low", "moderate", "important", "critical"])
    p.add_argument("--include", action="append", help="packages always installed (globs)")
    p.add_argument("--exclude", action="append", help="packages never installed (globs)")


def build_parser() -> argparse.ArgumentParser:
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--profile", help="a server from `fw profiles` (or FW_PROFILE)")
    common.add_argument("--json", action="store_true", help="JSON output with stable field names")
    common.add_argument("--jsonl", action="store_true", help="one JSON object per line (lists and streams)")
    common.add_argument("--yes", "-y", action="store_true", help="don't ask before changing hosts")

    root = argparse.ArgumentParser(prog="fw", description=__doc__, parents=[common],
                                   formatter_class=argparse.RawDescriptionHelpFormatter)
    root.add_argument("--version", action="version", version=f"fw {__version__}")
    sub = root.add_subparsers(dest="command", metavar="COMMAND")

    def cmd(name, fn, help, examples=None, parent=sub, **kw):
        p = parent.add_parser(name, parents=[common], help=help, description=help,
                              epilog=("examples:\n  " + examples.replace("\n", "\n  ")) if examples else None,
                              formatter_class=argparse.RawDescriptionHelpFormatter, **kw)
        p.set_defaults(fn=fn)
        return p

    p = cmd("login", cmd_login, "Connect to a FleetWright server with an API token")
    p.add_argument("--url", help="https://your-fleetwright:8443")
    p.add_argument("--fingerprint", help="the certificate's SHA-256, from Settings → HTTPS (pins it)")
    p.add_argument("--token-stdin", action="store_true", help="read the token from standard input")
    p.add_argument("--default", action="store_true", help="make this the default profile")
    cmd("logout", cmd_logout, "Forget a profile and its token")
    cmd("profiles", cmd_profiles, "The servers you've logged in to")
    cmd("whoami", cmd_whoami, "Who your token acts as, with which role")
    cmd("overview", cmd_overview, "The fleet at a glance, and what needs attention")

    hosts = sub.add_parser("hosts", help="Find, add and change hosts", parents=[common],
                           epilog="examples:\n  " + EXAMPLES["hosts"].replace("\n", "\n  "),
                           formatter_class=argparse.RawDescriptionHelpFormatter)
    hs = hosts.add_subparsers(dest="host_action", metavar="ACTION", required=True)
    p = cmd("list", cmd_hosts_list, "Hosts, with the hosts page's filters", parent=hs)
    p.add_argument("--status", default="all",
                   choices=["all", "updates", "security", "reboot", "unreachable", "never", "auto", "agent_old"])
    p.add_argument("--group", help="a group name or id, or 'none'")
    p.add_argument("--tag")
    p.add_argument("--os", help="as shown, e.g. 'Ubuntu 24.04.1 LTS'")
    p.add_argument("--mode", choices=["agent", "ssh"])
    p.add_argument("--search", help="host name, address, package or advisory")
    p.add_argument("--limit", type=int, help="at most this many (default: all)")
    p = cmd("show", cmd_hosts_show, "One host", parent=hs)
    p.add_argument("host")
    p = cmd("add", cmd_hosts_add, "Add an agentless (SSH) host", parent=hs)
    p.add_argument("name")
    p.add_argument("address", help="address[:port]")
    p.add_argument("--key", required=True, help="the stored SSH key (name or id)")
    p.add_argument("--group", dest="host_group")
    p.add_argument("--tag", action="append")
    p = cmd("edit", cmd_hosts_edit, "Change a host", parent=hs)
    p.add_argument("host")
    p.add_argument("--name")
    p.add_argument("--group", dest="host_group", help="group name or id, or 'none'")
    p.add_argument("--tags", help="replace its tags: a,b")
    p.add_argument("--held", help="replace its never-install list: 'nginx,postgresql-*'")
    p.add_argument("--address")
    p.add_argument("--port", type=int)
    p.add_argument("--key", help="SSH key (name or id)")
    p = cmd("remove", cmd_hosts_remove, "Remove hosts and their history", parent=hs)
    p.add_argument("hosts", nargs="+", metavar="HOST")
    p = cmd("scan", cmd_hosts_scan, "Scan hosts for updates now", parent=hs)
    p.add_argument("hosts", nargs="*", metavar="HOST")
    p.add_argument("--all", dest="all_hosts", action="store_true")
    p = cmd("tag", cmd_hosts_tag, "Add tags to hosts", parent=hs)
    p.add_argument("hosts", nargs="+", metavar="HOST")
    p.add_argument("--tags", action="append", required=True)
    p = cmd("move", cmd_hosts_move, "Move hosts to a group", parent=hs)
    p.add_argument("hosts", nargs="+", metavar="HOST")
    p.add_argument("--to", required=True, help="group name or id, or 'none'")
    p = cmd("forget-key", cmd_hosts_forget_key, "Clear a host's pinned SSH host key", parent=hs)
    p.add_argument("host")

    updates = sub.add_parser("updates", help="Pending updates", parents=[common])
    us = updates.add_subparsers(dest="updates_action", metavar="ACTION", required=True)
    p = cmd("list", cmd_updates, "A host's pending updates", "fw updates list web-07 --kind security", parent=us)
    p.add_argument("host")
    p.add_argument("--kind", default="all", choices=["all", "security", "kernel", "held"])

    p = cmd("history", cmd_history, "Package versions FleetWright changed on a host", "fw history web-07 --since 7d")
    p.add_argument("host")
    p.add_argument("--since", help="7d, 12h, 2w or a date")
    p.add_argument("--limit", type=int, default=200)

    run = sub.add_parser("run", help="Start, follow and steer runs", parents=[common],
                         epilog="examples:\n  " + EXAMPLES["run"].replace("\n", "\n  "),
                         formatter_class=argparse.RawDescriptionHelpFormatter)
    rs = run.add_subparsers(dest="run_action", metavar="ACTION", required=True)
    for kind, help_text in (("apply", "Install updates"), ("reboot", "Reboot hosts"), ("scan", "Scan hosts"),
                            ("auto-off", "Turn off hosts' own automatic updates"),
                            ("update-agents", "Update hosts' agents to the server's")):
        p = cmd(kind, cmd_run_start, help_text, EXAMPLES["run"] if kind == "apply" else None, parent=rs)
        p.set_defaults(run_kind=kind)
        add_target(p)
        if kind == "apply":
            add_selection(p)
            p.add_argument("--pick", action="append", help="just these packages, at the versions pending now")
        p.add_argument("--batch", help="hosts at a time: 10, or 10%%")
        p.add_argument("--canary", action="store_true", help="one host on its own first")
        p.add_argument("--max-failures", type=int, default=0, help="stop after this many failed hosts")
        p.add_argument("--reboot", default="never", choices=["never", "if-needed", "always"])
        p.add_argument("--title")
        p.add_argument("--dry-run", action="store_true", help="show what it would do, and stop")
        p.add_argument("--wait", action="store_true", help="wait for the end; exit 1 if any host failed")
        p.add_argument("--follow", action="store_true", help="with --wait: show the hosts' output as it comes")
        p.add_argument("--idempotency-key", help="retrying with the same key never starts a second run")
    p = cmd("list", cmd_runs_list, "Recent runs", parent=rs)
    p.add_argument("--status", choices=["running", "paused", "done", "failed", "aborted", "stopped"])
    p.add_argument("--limit", type=int, default=20)
    p = cmd("show", cmd_run_show, "A run and its hosts", parent=rs)
    p.add_argument("run", type=int)
    p = cmd("watch", cmd_run_watch, "Follow a run live; exit 1 if a host failed", parent=rs)
    p.add_argument("run", type=int)
    for action, help_text in (("pause", "Pause after the current batch"), ("resume", "Resume a paused run"),
                              ("abort", "Abort a run"), ("retry", "A new run on the hosts that failed")):
        p = cmd(action, cmd_run_control, help_text, parent=rs)
        p.add_argument("run", type=int)
        if action == "retry":
            p.add_argument("--wait", action="store_true")
        p.set_defaults(run_action=action)
    p = cmd("task", cmd_task, "One host's task in a run, with its full log")
    p.add_argument("task", type=int)

    pol = sub.add_parser("policies", help="Auto-install policies", parents=[common])
    ps = pol.add_subparsers(dest="policy_action", metavar="ACTION", required=True)
    cmd("list", cmd_policies, "Every policy", parent=ps)
    p = cmd("create", cmd_policies, "Create a policy from a JSON file (the API's PolicyIn)", parent=ps)
    p.add_argument("file")
    for action, help_text in (("show", "A policy, and what it would install now"), ("enable", "Switch it on"),
                              ("disable", "Switch it off"), ("run", "Run it now"), ("delete", "Delete it")):
        p = cmd(action, cmd_policies, help_text, parent=ps)
        p.add_argument("policy", type=int)
        if action == "run":
            p.add_argument("--wait", action="store_true")
            p.add_argument("--idempotency-key")

    p = cmd("book", cmd_book, "Book a one-off install for a window", EXAMPLES["book"])
    p.add_argument("hosts", nargs="*", metavar="HOST")
    p.add_argument("--group", action="append")
    p.add_argument("--tag", action="append")
    p.add_argument("--window", required=True, help="'2026-11-12 22:00/23:30' (UTC)")
    add_selection(p)
    p.add_argument("--pin", action="append", help="just these packages, pinned to the versions pending now")
    p.add_argument("--needs-approval", action="store_true")
    p.add_argument("--reboot", default="if-needed", choices=["never", "if-needed", "always"])
    p.add_argument("--batch", type=int, default=1, help="hosts at a time")
    p.add_argument("--on-close", default="finish-started", choices=["finish-started", "stop", "carry-on"],
                   help="when the window closes: running hosts finish and no new ones start, or carry on"
                        " until done; 'stop' is a legacy alias for 'finish-started'")
    p.add_argument("--title")

    bk = sub.add_parser("bookings", help="Booked installs", parents=[common])
    bs = bk.add_subparsers(dest="booking_action", metavar="ACTION", required=True)
    cmd("list", cmd_bookings, "Upcoming and recent bookings", parent=bs)
    for action in ("approve", "cancel"):
        p = cmd(action, cmd_bookings, f"{action.capitalize()} a booking", parent=bs)
        p.add_argument("booking", type=int)

    p = cmd("audit", cmd_audit, "The audit log")
    p.add_argument("--limit", type=int, default=50)

    grp = sub.add_parser("groups", help="Host groups", parents=[common])
    gs = grp.add_subparsers(dest="group_action", metavar="ACTION", required=True)
    cmd("list", cmd_simple_list("/groups", "groups", [("id", "id"), ("name", "name"), ("hosts", "hosts"),
                                                      ("description", "description")]), "Groups", parent=gs)
    p = cmd("add", cmd_groups, "Add a group", parent=gs)
    p.add_argument("name")
    p.add_argument("--description")
    p = cmd("rename", cmd_groups, "Rename a group", parent=gs)
    p.add_argument("group")
    p.add_argument("name")
    p.add_argument("--description")
    p = cmd("remove", cmd_groups, "Delete a group (its hosts stay)", parent=gs)
    p.add_argument("group")

    keys = sub.add_parser("keys", help="Stored SSH keys", parents=[common])
    ks = keys.add_subparsers(dest="key_action", metavar="ACTION", required=True)
    cmd("list", cmd_simple_list("/ssh-keys", "keys", [("id", "id"), ("name", "name"), ("username", "user"),
                                                      ("hosts", "hosts"), ("public_key", "public key")]),
        "SSH keys", parent=ks)
    p = cmd("add", cmd_keys, "Store a key, or generate one", parent=ks)
    p.add_argument("name")
    p.add_argument("--user", default="root")
    p.add_argument("--private-key-file", help="leave out to generate an ed25519 key")
    p = cmd("remove", cmd_keys, "Delete a key", parent=ks)
    p.add_argument("key")

    users = sub.add_parser("users", help="People and their roles", parents=[common])
    uss = users.add_subparsers(dest="user_action", metavar="ACTION", required=True)
    cmd("list", cmd_simple_list("/users", "users", [("id", "id"), ("name", "name"), ("email", "email"),
                                                    ("role", "role"), ("last_login", "last sign-in")]),
        "Everyone", parent=uss)
    p = cmd("add", cmd_users, "Add someone (prints their setup link)", parent=uss)
    p.add_argument("email")
    p.add_argument("name")
    p.add_argument("role", choices=["viewer", "operator", "admin"])
    p = cmd("role", cmd_users, "Change someone's role", parent=uss)
    p.add_argument("user", type=int)
    p.add_argument("role", choices=["viewer", "operator", "admin"])
    p = cmd("link", cmd_users, "A new setup link for someone", parent=uss)
    p.add_argument("user", type=int)
    p = cmd("remove", cmd_users, "Remove someone", parent=uss)
    p.add_argument("user", type=int)

    tok = sub.add_parser("tokens", help="API tokens", parents=[common])
    ts = tok.add_subparsers(dest="token_action", metavar="ACTION", required=True)
    p = cmd("list", cmd_tokens, "Your tokens", parent=ts)
    p.add_argument("--everyone", action="store_true", help="everyone's (admins)")
    p = cmd("create", cmd_tokens, "A new token (printed once)", parent=ts)
    p.add_argument("name")
    p.add_argument("--role", choices=["viewer", "operator", "admin"])
    p.add_argument("--expires-days", type=int)
    p = cmd("revoke", cmd_tokens, "Revoke a token", parent=ts)
    p.add_argument("token", type=int)

    ag = sub.add_parser("agents", help="Agents and their version", parents=[common])
    ags = ag.add_subparsers(dest="agent_action", metavar="ACTION", required=True)
    cmd("status", cmd_agents, "Agent counts and the version the server hands out", parent=ags)
    p = cmd("update", cmd_agents, "Update every agent that differs from the server's", parent=ags)
    p.add_argument("--wait", action="store_true")

    en = sub.add_parser("enrol", help="Agent enrolment tokens", parents=[common])
    ens = en.add_subparsers(dest="enrol_action", metavar="ACTION", required=True)
    p = cmd("create", cmd_enrol, "A token and the install command to run on hosts", parent=ens)
    p.add_argument("--label")
    p.add_argument("--group", dest="host_group")
    p.add_argument("--tag", action="append")
    p.add_argument("--uses", type=int)
    p.add_argument("--days", type=int, default=7)
    p = cmd("revoke", cmd_enrol, "Revoke an enrolment token", parent=ens)
    p.add_argument("token", type=int)

    nt = sub.add_parser("notifications", help="Notification channels", parents=[common])
    nts = nt.add_subparsers(dest="notify_action", metavar="ACTION", required=True)
    cmd("list", cmd_notifications, "Channels and their last result", parent=nts)
    p = cmd("test", cmd_notifications, "Send a test through a channel", parent=nts)
    p.add_argument("channel", type=int)

    cmd("backups", cmd_backups, "The last backup; exit 1 if it failed or is overdue")
    cmd("https", cmd_https, "The certificate the server uses")
    p = cmd("completion", cmd_completion, "Shell completion: eval \"$(fw completion bash)\"")
    p.add_argument("shell", choices=["bash", "zsh", "fish"])
    p = cmd("help", cmd_help, "Help for a command, with examples")
    p.add_argument("topic", nargs="*")
    return root


def cmd_help(args, out: Out):
    build_parser().parse_args([*args.topic, "--help"])
    return OK


def cmd_completion(args, out: Out):
    from .complete import script
    print(script(build_parser(), args.shell))
    return OK


LOCAL = {cmd_login, cmd_logout, cmd_profiles, cmd_help, cmd_completion}


def main(argv: Optional[list[str]] = None) -> int:
    parser = build_parser()
    argv = sys.argv[1:] if argv is None else argv
    try:
        args = parser.parse_args(argv)
    except SystemExit as e:          # argparse: --help is 0, a mistake is 2
        return int(e.code or 0)
    if not getattr(args, "fn", None):
        parser.print_help()
        return USAGE
    out = Out(args)
    try:
        if args.fn in LOCAL:
            return args.fn(args, out)
        _, prof, token = resolve_profile(args.profile)
        api = Client(prof["url"], token, prof.get("fingerprint"))
        return args.fn(args, out, api)
    except CLIError as e:
        if out.json or out.jsonl:
            print(json.dumps({"error": {"message": e.message, "errors": e.details, "exit": e.code}}),
                  file=sys.stderr)
        else:
            print(f"fw: {e.message}", file=sys.stderr)
            for d in e.details:
                if d != e.message:
                    print(f"  - {d}", file=sys.stderr)
        return e.code
    except KeyboardInterrupt:
        return FAILED
    except BrokenPipeError:          # `fw run watch 42 | head`: stop quietly
        sys.stderr.close()
        return OK


if __name__ == "__main__":
    sys.exit(main())


