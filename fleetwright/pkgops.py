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
    facts                  what the host is (OS, kernel, boot id, instance id)
    scan                   refresh the package lists and list pending updates
    apply  <selection>     install the updates a selection picks (JSON argument)
    reboot                 reboot in a few seconds, returning first
    auto_off               stop unattended-upgrades / dnf-automatic installing updates

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
import uuid

VERSION = "0.2.1"
RESULT_PREFIX = "FWRESULT "
# An id for this installation, made after install time. A container image's
# /etc/machine-id can be copied from its template; this file normally isn't.
INSTANCE_ID_PATH = "/etc/fleetwright-agent/instance-id"

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
# Ubuntu hides phased updates from `apt-get upgrade`. A second simulation that
# includes them says exactly what is being withheld; apt elsewhere ignores the
# option, so the two simulations match and nothing is reported.
APT_PHASED_OPT = ["-o", "APT::Get::Always-Include-Phased-Updates=true"]


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


def instance_id() -> str:
    """This installation's uuid: created once, then read back on every call.

    Reinstalling the agent keeps it. Two containers from one image on one kernel
    can share a machine id, a hostname and a boot id, but not this file, so the
    gateway can tell them apart when they enrol. If /etc is read-only, an id is
    still sent, but a new one is made each time the agent starts.
    """
    value = _read(INSTANCE_ID_PATH)
    try:
        uuid.UUID(value)
        return value
    except ValueError:
        pass
    value = str(uuid.uuid4())
    tmp = INSTANCE_ID_PATH + ".tmp"
    try:
        os.makedirs(os.path.dirname(INSTANCE_ID_PATH), mode=0o700, exist_ok=True)
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as f:
            f.write(value + "\n")
        os.replace(tmp, INSTANCE_ID_PATH)
    except OSError:
        try:
            os.unlink(tmp)
        except OSError:
            pass
    return value


def facts() -> dict:
    osr = _os_release()
    uptime = _read("/proc/uptime").split()
    booted = int(time.time() - float(uptime[0])) if uptime else None
    return {
        "hostname": socket.gethostname(),
        "machine_id": _read("/etc/machine-id"),
        "instance_id": instance_id(),
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


def phased_updates_from_simulations(normal: str, with_phased: str) -> list[str]:
    """Upgrades apt only plans when phasing is ignored, sorted by package name.

    New packages in the second simulation are dependencies of those upgrades,
    not phased updates themselves.
    """
    normal_names = {p["name"] for p in parse_apt_simulation(normal)}
    return sorted({p["name"] for p in parse_apt_simulation(with_phased)
                   if p["current"] is not None and p["name"] not in normal_names})


def apt_installed() -> dict[str, str]:
    _, out = run(["dpkg-query", "-W", "-f", "${Package}:${Architecture} ${Version} ${db:Status-Abbrev}\n"],
                 quiet=True)
    found = {}
    for line in out.splitlines():
        parts = line.split()
        if len(parts) >= 3 and parts[2].startswith("ii"):
            found[parts[0]] = parts[1]
    return found


def _apt_simulate_upgrade(log, extra_opts=()) -> str:
    _, out = run(["apt-get", "-s", "upgrade", "--with-new-pkgs"] + APT_OPTS[:2] + list(extra_opts),
                 log, env=APT_ENV, quiet=True)
    return out


def apt_scan(log, refresh: bool) -> tuple[list[dict], list[str]]:
    """Return (pending, phased updates Ubuntu is currently holding back)."""
    if refresh:
        run(["apt-get", "update", "-q"] + APT_OPTS[:2], log, env=APT_ENV)
    out = _apt_simulate_upgrade(log)
    pending = parse_apt_simulation(out)
    try:
        all_out = _apt_simulate_upgrade(log, APT_PHASED_OPT)
    except (OpError, OSError) as e:
        if log:
            log("phased-update check unavailable: " + str(e).splitlines()[0])
        return pending, []
    return pending, phased_updates_from_simulations(out, all_out)


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


# ─── Other tools that install updates ───────────────────────────────────────
# unattended-upgrades (Ubuntu, on by default) and dnf-automatic install updates by
# themselves. If one runs during a FleetWright install, its changes land in the
# before/after diff and are recorded as FleetWright's.

APT_UU_OFF_FILE = "/etc/apt/apt.conf.d/99fleetwright-no-unattended-upgrades"
# dnf5 (Fedora 41+) has one timer that installs only if apply_updates is on; dnf4
# (RHEL, older Fedora) also has one that always installs.
DNF_AUTO_TIMERS = {"dnf5-automatic.timer": "config", "dnf-automatic.timer": "config",
                   "dnf-automatic-install.timer": "always"}
DNF_AUTO_CONFS = ("/etc/dnf/automatic.conf", "/usr/share/dnf5/dnf5-plugins/automatic.conf")

# APT::Periodic::Unattended-Upgrade "1";
# Unattended-Upgrade::Allowed-Origins:: "${distro_id}:${distro_codename}-security";
_APT_CONF_LINE = re.compile(r'^(\S+?)(::)? "(.*)";$')


def parse_apt_config(text: str) -> tuple[str, list[str]]:
    """apt-config dump -> (APT::Periodic::Unattended-Upgrade, the origins unattended-upgrades takes)."""
    periodic, origins = "0", []
    for line in text.splitlines():
        m = _APT_CONF_LINE.match(line.strip())
        if not m:
            continue
        key, is_item, value = m.groups()
        if key == "APT::Periodic::Unattended-Upgrade":
            periodic = value
        elif is_item and key in ("Unattended-Upgrade::Allowed-Origins", "Unattended-Upgrade::Origins-Pattern"):
            origins.append(value)
    return periodic, origins


def uu_scope(origins: list[str]) -> str:
    """What unattended-upgrades installs. The release pocket itself (no suffix) never
    changes after release, so only -updates, -backports, -proposed or a pattern
    that doesn't name security count as 'other'."""
    other = any(re.search(r"-(updates|backports|proposed)\b", o)
                or ("=" in o and "security" not in o.lower()) for o in origins)
    return "security and other updates" if other else "security updates"


def parse_dnf_automatic_conf(text: str) -> tuple[bool, str]:
    """automatic.conf -> (apply_updates, upgrade_type)."""
    apply, kind, section = False, "default", ""
    for line in text.splitlines():
        line = line.split("#", 1)[0].strip()
        if line.startswith("["):
            section = line.strip("[]").strip()
        elif "=" in line and section == "commands":
            k, v = (s.strip() for s in line.split("=", 1))
            if k == "apply_updates":
                apply = v.lower() in ("yes", "true", "1", "on")
            elif k == "upgrade_type":
                kind = v.lower()
    return apply, kind


def _unit_on(unit: str) -> bool:
    if not shutil.which("systemctl"):
        return False
    for verb, want in (("is-enabled", ("enabled", "enabled-runtime")), ("is-active", ("active",))):
        try:
            _, out = run(["systemctl", verb, unit], ok_codes=range(256), quiet=True)
        except (OpError, OSError):
            continue
        if out.strip().splitlines()[:1] and out.strip().splitlines()[0] in want:
            return True
    return False


def apt_auto_updates() -> list[dict]:
    if not shutil.which("unattended-upgrade"):
        return []
    _, out = run(["apt-config", "dump"], quiet=True)
    periodic, origins = parse_apt_config(out)
    timer = _unit_on("apt-daily-upgrade.timer")
    installs = periodic not in ("0", "") and timer
    if installs:
        detail = f"installs {uu_scope(origins)} daily"
    elif not timer:
        detail = "installed, but apt-daily-upgrade.timer is off"
    else:
        detail = "installed, but turned off (APT::Periodic::Unattended-Upgrade 0)"
    return [{"tool": "unattended-upgrades", "installs": installs, "detail": detail}]


def dnf_auto_updates() -> list[dict]:
    conf = next((_read(p) for p in DNF_AUTO_CONFS if os.path.exists(p)), "")
    apply, kind = parse_dnf_automatic_conf(conf)
    found, seen = [], set()
    for timer, mode in DNF_AUTO_TIMERS.items():
        if not _unit_on(timer):
            continue
        # On Fedora 41+ dnf-automatic.timer is an alias of dnf5-automatic.timer.
        _, real = run(["systemctl", "show", "-p", "Id", "--value", timer], ok_codes=range(256), quiet=True)
        if (real.strip() or timer) in seen:
            continue
        seen.add(real.strip() or timer)
        installs = mode == "always" or apply
        what = "security updates" if kind == "security" else "all updates"
        found.append({"tool": timer.removesuffix(".timer"), "installs": installs,
                      "detail": f"installs {what}" if installs else "downloads or notifies only (apply_updates = no)",
                      "unit": timer})
    return found


def auto_updates(fam: str) -> list[dict]:
    """Never fails a scan: a problem here is reported as an entry."""
    try:
        return apt_auto_updates() if fam == "apt" else dnf_auto_updates()
    except (OpError, OSError) as e:
        return [{"tool": "unknown", "installs": False, "detail": f"couldn't check: {str(e).splitlines()[0]}"}]


def op_auto_off(log=_print_log) -> dict:
    """Stop the tools above installing updates, then rescan. Reversible: delete the
    apt file, or systemctl enable --now the timer."""
    fam = family()
    log("▸ turn off automatic updates")
    found = [a for a in auto_updates(fam) if a["installs"]]
    if not found:
        log("nothing here installs updates by itself")
    elif fam == "apt":
        with open(APT_UU_OFF_FILE, "w") as f:
            f.write("// Written by FleetWright, which installs updates on this host.\n"
                    "// Delete this file to let unattended-upgrades install them again.\n"
                    'APT::Periodic::Unattended-Upgrade "0";\n')
        log(f"wrote {APT_UU_OFF_FILE}")
    else:
        for a in found:
            run(["systemctl", "disable", "--now", a["unit"]], log)
    return op_scan(log, refresh=False)


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
    if fam == "apt":
        pending, phased = apt_scan(log, refresh)
    else:
        pending, phased = dnf_scan(log, refresh), []
    reboot = apt_reboot_required() if fam == "apt" else dnf_reboot_required()
    holds = apt_holds() if fam == "apt" else dnf_holds()
    s = _summary(pending)
    log(f"{s['pending_count']} updates pending, {s['security_count']} security"
        + (" · reboot required" if reboot else ""))
    if phased:
        log(f"{len(phased)} held back by Ubuntu phasing")
    autos = auto_updates(fam)
    for a in autos:
        if a["installs"]:
            log(f"note: {a['tool']} {a['detail']}, outside FleetWright")
    return {"ok": True, "facts": facts(), "pending": pending, "reboot_required": reboot,
            "os_holds": holds, "phased_updates": phased, "auto_updates": autos, **s}


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
        elif op == "auto_off":
            result = op_auto_off()
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
