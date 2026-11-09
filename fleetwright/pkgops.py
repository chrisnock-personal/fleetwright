#!/usr/bin/env python3
"""
pkgops.py
~~~~~~~~~
Everything FleetWright does on a host, in one standard-library-only file.

The agent imports it. For agentless (SSH) hosts the server pipes this same
file to ``sudo python3 - <op>`` on the host, so both ways of reaching a host
run exactly the same code.

Run as a script it prints progress lines, then one final line:
    FWRESULT {"ok": true, ...}

Operations
    facts                  what the host is (OS, kernel, boot id)
    scan                   refresh the package lists and list pending updates
    apply  <selection>     install the updates a selection picks (JSON argument)
    reboot                 reboot in a few seconds, returning first

Supported: Ubuntu (apt) and Fedora (dnf5). Other apt/dnf distributions
probably work but aren't tested.
"""

from __future__ import annotations

import fnmatch
import json
import os
import re
import shutil
import socket
import subprocess
import sys
import time

VERSION = "0.1.0"
RESULT_PREFIX = "FWRESULT "

SEVERITY_ORDER = {"low": 1, "moderate": 2, "important": 3, "critical": 4}
KERNEL_PATTERNS = ("kernel", "kernel-core", "kernel-modules*", "kernel-uki-virt",
                   "linux-image-*", "linux-headers-*", "linux-modules-*", "linux-generic*",
                   "linux-virtual*", "linux-image", "linux-headers")
# Commands get their arguments as a list, never through a shell; these also stop a
# value that starts with "-" being read as an option.
PKG_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9+._-]*$")
PKG_VERSION = re.compile(r"^[A-Za-z0-9][A-Za-z0-9+.~^:_-]*$")
APT_ENV = {"DEBIAN_FRONTEND": "noninteractive", "NEEDRESTART_MODE": "a",
           "APT_LISTCHANGES_FRONTEND": "none"}
APT_OPTS = ["-o", "DPkg::Lock::Timeout=600", "-o", "Dpkg::Options::=--force-confdef",
            "-o", "Dpkg::Options::=--force-confold"]


class OpError(Exception):
    pass


def _print_log(line: str) -> None:
    print(line, flush=True)


# ─── Running commands ───────────────────────────────────────────────────────

def run(cmd: list[str], log=None, *, env: dict | None = None, ok_codes=(0,),
        quiet: bool = False) -> tuple[int, str]:
    """Run a command, streaming its output to log unless quiet. Returns (rc, output)."""
    full_env = dict(os.environ, LC_ALL="C.UTF-8", **(env or {}))
    if log and not quiet:
        log("$ " + " ".join(cmd))
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                            stdin=subprocess.DEVNULL, env=full_env, text=True, errors="replace")
    out = []
    for line in proc.stdout:
        line = line.rstrip("\n")
        out.append(line)
        if log and not quiet:
            log("  " + line)
    rc = proc.wait()
    if rc not in ok_codes:
        tail = "\n".join(out[-15:])
        raise OpError(f"{cmd[0]} {cmd[1] if len(cmd) > 1 else ''} exited with {rc}\n{tail}".strip())
    return rc, "\n".join(out)


# ─── Facts ──────────────────────────────────────────────────────────────────

def _os_release() -> dict:
    data = {}
    try:
        with open("/etc/os-release") as f:
            for line in f:
                if "=" in line:
                    k, v = line.rstrip("\n").split("=", 1)
                    data[k] = v.strip().strip('"')
    except OSError:
        pass
    return data


def family() -> str:
    if shutil.which("apt-get") and shutil.which("dpkg-query"):
        return "apt"
    if shutil.which("dnf"):
        return "dnf"
    raise OpError("Neither apt nor dnf found: this host's package manager isn't supported")


def _read(path: str) -> str:
    try:
        with open(path) as f:
            return f.read().strip()
    except OSError:
        return ""


def facts() -> dict:
    osr = _os_release()
    uptime = _read("/proc/uptime").split()
    booted = int(time.time() - float(uptime[0])) if uptime else None
    return {
        "hostname": socket.gethostname(),
        "machine_id": _read("/etc/machine-id"),
        "os_id": osr.get("ID", ""),
        "os_version": osr.get("VERSION_ID", ""),
        "os_pretty": osr.get("PRETTY_NAME", ""),
        "family": family(),
        "kernel": os.uname().release,
        "boot_id": _read("/proc/sys/kernel/random/boot_id"),
        "booted_at": booted,
        "pkgops": VERSION,
    }


def is_kernel(name: str) -> bool:
    return any(fnmatch.fnmatchcase(name, p) for p in KERNEL_PATTERNS)


# ─── apt ────────────────────────────────────────────────────────────────────

# Inst openssl [3.0.13-0ubuntu3.5] (3.0.13-0ubuntu3.6 Ubuntu:24.04/noble-updates, Ubuntu:24.04/noble-security [amd64])
_APT_INST = re.compile(r"^Inst (\S+) (?:\[([^\]]*)\] )?\((\S+) (.*?) \[([^\]]+)\]\)")


def parse_apt_simulation(text: str) -> list[dict]:
    pending = []
    for line in text.splitlines():
        m = _APT_INST.match(line)
        if not m:
            continue
        name, current, available, sources, arch = m.groups()
        pockets = [s.split("/", 1)[-1] for s in sources.split(", ")]
        security = any(p.endswith("-security") for p in pockets)
        pending.append({
            "name": name, "arch": arch, "current": current or None, "available": available,
            "source": ",".join(pockets), "is_security": security, "is_kernel": is_kernel(name),
            "kind": "security" if security else "bugfix", "severity": None, "advisory": None,
        })
    return pending


def apt_installed() -> dict[str, str]:
    _, out = run(["dpkg-query", "-W", "-f", "${Package}:${Architecture} ${Version} ${db:Status-Abbrev}\n"],
                 quiet=True)
    found = {}
    for line in out.splitlines():
        parts = line.split()
        if len(parts) >= 3 and parts[2].startswith("ii"):
            found[parts[0]] = parts[1]
    return found


def apt_scan(log, refresh: bool) -> list[dict]:
    if refresh:
        run(["apt-get", "update", "-q"] + APT_OPTS[:2], log, env=APT_ENV)
    _, out = run(["apt-get", "-s", "upgrade", "--with-new-pkgs"] + APT_OPTS[:2], log,
                 env=APT_ENV, quiet=True)
    return parse_apt_simulation(out)


def apt_reboot_required() -> bool:
    return os.path.exists("/var/run/reboot-required")


def apt_holds() -> list[str]:
    _, out = run(["apt-mark", "showhold"], quiet=True)
    return [l.strip() for l in out.splitlines() if l.strip()]


def apt_install(chosen: list[dict], log) -> None:
    args = []
    for p in chosen:
        spec = f"{p['name']}:{p['arch']}" if p["arch"] not in ("all", "") else p["name"]
        args.append(f"{spec}={p['available']}")
    run(["apt-get", "-y", "-q"] + APT_OPTS + ["install", "--only-upgrade"] + args, log, env=APT_ENV)


# ─── dnf ────────────────────────────────────────────────────────────────────

def split_nevra(nevra: str) -> tuple[str, str, str]:
    """'NetworkManager-1:1.56.1-2.fc44.x86_64' -> ('NetworkManager', '1:1.56.1-2.fc44', 'x86_64')"""
    base, _, arch = nevra.rpartition(".")
    name, version, release = base.rsplit("-", 2)
    return name, f"{version}-{release}", arch


def parse_dnf_check_upgrade(text: str) -> list[dict]:
    pending = []
    for line in text.splitlines():
        parts = line.split()
        if line.startswith((" ", "\t")) or len(parts) != 3 or "." not in parts[0]:
            continue  # headers, "Obsoleting packages" continuation lines
        name, _, arch = parts[0].rpartition(".")
        pending.append({"name": name, "arch": arch, "current": None, "available": parts[1],
                        "source": parts[2], "is_security": False, "is_kernel": is_kernel(name),
                        "kind": "bugfix", "severity": None, "advisory": None})
    return pending


KIND_RANK = {"security": 3, "bugfix": 2, "unspecified": 2, "enhancement": 1, "newpackage": 1}


def merge_dnf_advisories(pending: list[dict], advisories: list[dict]) -> None:
    by_key = {(p["name"], p["arch"]): p for p in pending}
    best: dict = {}
    for adv in advisories:
        try:
            name, evr, arch = split_nevra(adv["nevra"])
        except (KeyError, ValueError):
            continue
        p = by_key.get((name, arch))
        if not p:
            continue
        kind = adv.get("type", "unspecified")
        sev = (adv.get("severity") or "").lower()
        sev = sev if sev in SEVERITY_ORDER else None
        rank = (KIND_RANK.get(kind, 0), SEVERITY_ORDER.get(sev or "", 0))
        if (name, arch) in best and best[(name, arch)] >= rank:
            continue
        best[(name, arch)] = rank
        p["kind"] = "bugfix" if kind == "unspecified" else kind
        p["is_security"] = kind == "security"
        p["severity"] = sev
        p["advisory"] = adv.get("name")


def dnf_installed() -> dict[str, str]:
    _, out = run(["rpm", "-qa", "--qf", "%{NAME}.%{ARCH} %{EPOCH}:%{VERSION}-%{RELEASE}\n"], quiet=True)
    found = {}
    for line in out.splitlines():
        parts = line.split()
        if len(parts) == 2:
            evr = parts[1][len("(none):"):] if parts[1].startswith("(none):") else parts[1]
            if evr.startswith("0:"):
                evr = evr[2:]
            # several installed kernels: keep the newest-listed one
            found[parts[0]] = evr
    return found


def dnf_scan(log, refresh: bool) -> list[dict]:
    if refresh:
        run(["dnf", "-q", "makecache"], log)
    _, out = run(["dnf", "-q", "check-upgrade"], log, ok_codes=(0, 100), quiet=True)
    pending = parse_dnf_check_upgrade(out)
    try:
        _, adv = run(["dnf", "-q", "advisory", "list", "--updates", "--json"], quiet=True)
        merge_dnf_advisories(pending, json.loads(adv or "[]"))
    except (OpError, ValueError) as e:
        if log:
            log(f"advisory data unavailable: {str(e).splitlines()[0]}")
    installed = dnf_installed()
    for p in pending:
        p["current"] = installed.get(f"{p['name']}.{p['arch']}")
    return pending


def dnf_reboot_required() -> bool:
    try:
        rc, _ = run(["dnf", "-q", "needs-restarting", "-r"], ok_codes=(0, 1), quiet=True)
        return rc == 1
    except (OpError, FileNotFoundError):
        return False


def dnf_holds() -> list[str]:
    try:
        _, out = run(["dnf", "-q", "versionlock", "list"], quiet=True)
    except (OpError, FileNotFoundError):
        return []
    return [l.strip() for l in out.splitlines() if l.strip() and not l.startswith("#")]


def dnf_install(chosen: list[dict], log) -> None:
    run(["dnf", "-y", "upgrade"] + [f"{p['name']}-{p['available']}.{p['arch']}" for p in chosen], log)


# ─── Choosing what to install ───────────────────────────────────────────────

def _matches(name: str, patterns) -> bool:
    return any(fnmatch.fnmatchcase(name, pat) for pat in patterns or ())


def select(pending: list[dict], selection: dict, held=()) -> tuple[list[dict], list[dict]]:
    """Returns (chosen, skipped). skipped items carry a 'why'."""
    mode = selection.get("mode", "all")
    exclude = list(selection.get("exclude") or []) + list(held or [])
    chosen, skipped = [], []
    pinned = {}
    if mode == "packages":
        pinned = {(p["name"], p.get("arch", "")): p.get("version") for p in selection.get("packages") or []}
        pinned.update({(p["name"], ""): p.get("version") for p in selection.get("packages") or []
                       if not p.get("arch")})
    kinds = set(selection.get("kinds") or [])
    min_sev = SEVERITY_ORDER.get((selection.get("min_severity") or "").lower(), 0)
    include = selection.get("include") or []

    for p in pending:
        if p["current"] is None:
            continue  # a new package (a new kernel): comes in as a dependency
        if _matches(p["name"], exclude):
            skipped.append(dict(p, why="excluded or held"))
            continue
        if mode == "all":
            chosen.append(p)
        elif mode == "packages":
            want = pinned.get((p["name"], p["arch"]), pinned.get((p["name"], "")))
            if want is None:
                continue
            if want != p["available"]:
                skipped.append(dict(p, why=f"pinned to {want}, now {p['available']}"))
                continue
            chosen.append(p)
        else:
            sev = SEVERITY_ORDER.get(p.get("severity") or "", 0)
            # No severity (all of Ubuntu, some Fedora advisories): counts as meeting any minimum.
            sev_ok = sev == 0 or sev >= min_sev
            take = ((("security" in kinds) and p["is_security"] and sev_ok)
                    or (("kernel" in kinds) and p["is_kernel"])
                    or (("bugfix" in kinds) and p["kind"] == "bugfix" and not p["is_security"])
                    or (("enhancement" in kinds) and p["kind"] == "enhancement")
                    or _matches(p["name"], include))
            if take:
                chosen.append(p)
    for p in chosen:
        if not PKG_NAME.match(p["name"]) or not PKG_VERSION.match(p["available"]):
            raise OpError(f"refusing odd package name or version: {p['name']} {p['available']}")
    return chosen, skipped


# ─── Operations ─────────────────────────────────────────────────────────────

def _summary(pending: list[dict]) -> dict:
    return {"pending_count": sum(1 for p in pending if p["current"] is not None),
            "security_count": sum(1 for p in pending if p["is_security"] and p["current"] is not None)}


def op_scan(log=_print_log, refresh: bool = True) -> dict:
    fam = family()
    log(f"▸ scan ({fam})")
    pending = apt_scan(log, refresh) if fam == "apt" else dnf_scan(log, refresh)
    reboot = apt_reboot_required() if fam == "apt" else dnf_reboot_required()
    holds = apt_holds() if fam == "apt" else dnf_holds()
    s = _summary(pending)
    log(f"{s['pending_count']} updates pending, {s['security_count']} security"
        + (" · reboot required" if reboot else ""))
    return {"ok": True, "facts": facts(), "pending": pending, "reboot_required": reboot,
            "os_holds": holds, **s}


def op_apply(selection: dict, log=_print_log) -> dict:
    fam = family()
    before_scan = op_scan(log, refresh=True)
    chosen, skipped = select(before_scan["pending"], selection, selection.get("held") or [])
    for s in skipped:
        log(f"skip {s['name']}: {s['why']}")
    if not chosen:
        log("▸ nothing to install")
        return dict(before_scan, changes=[], skipped=[{"name": s["name"], "why": s["why"]} for s in skipped],
                    planned=0)
    log(f"▸ plan: {len(chosen)} packages")
    for p in chosen:
        log(f"  {p['name']:<28} {p['current']} → {p['available']}")
    before = apt_installed() if fam == "apt" else dnf_installed()
    log("▸ apply")
    if fam == "apt":
        apt_install(chosen, log)
    else:
        dnf_install(chosen, log)
    after = apt_installed() if fam == "apt" else dnf_installed()
    changes = [{"name": k, "from": before.get(k), "to": v} for k, v in sorted(after.items())
               if before.get(k) != v]
    changes += [{"name": k, "from": v, "to": None} for k, v in sorted(before.items()) if k not in after]
    log("▸ verify")
    after_scan = op_scan(log, refresh=False)
    log(f"✓ {len(changes)} packages changed")
    return dict(after_scan, changes=changes, planned=len(chosen),
                skipped=[{"name": s["name"], "why": s["why"]} for s in skipped])


def op_reboot(log=_print_log) -> dict:
    log("▸ reboot in 5 seconds")
    boot_id = _read("/proc/sys/kernel/random/boot_id")
    if shutil.which("systemd-run"):
        run(["systemd-run", "--on-active=5", "--timer-property=AccuracySec=1s",
             "/usr/bin/systemctl", "reboot"], log)
    else:
        run(["shutdown", "-r", "+1"], log)
    return {"ok": True, "boot_id_before": boot_id}


def main(argv: list[str]) -> int:
    if not argv:
        print(__doc__)
        return 2
    op = argv[0]
    try:
        if op == "facts":
            result = {"ok": True, "facts": facts()}
        elif op == "scan":
            result = op_scan()
        elif op == "apply":
            result = op_apply(json.loads(argv[1]) if len(argv) > 1 else {"mode": "all"})
        elif op == "reboot":
            result = op_reboot()
        else:
            result = {"ok": False, "error": f"unknown operation {op}"}
    except OpError as e:
        result = {"ok": False, "error": str(e)}
    except Exception as e:  # noqa: BLE001 - always end with a result line
        result = {"ok": False, "error": f"{type(e).__name__}: {e}"}
    print(RESULT_PREFIX + json.dumps(result), flush=True)
    return 0 if result.get("ok") else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
