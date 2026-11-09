"""Tests for the parts with no database or network: parsing, choosing, scheduling, batching."""

from datetime import datetime, time, timezone

import pytest

from fleetwright import pkgops
from fleetwright.fleet import batches_for, describe_selection
from fleetwright.schedule import describe, next_run
from fleetwright.views.hosts import parse_host_lines

APT_SIM = """\
NOTE: This is only a simulation!
Inst liblzma5 [5.6.1+really5.4.5-1ubuntu0.3] (5.6.1+really5.4.5-1ubuntu0.4 Ubuntu:24.04/noble-updates, Ubuntu:24.04/noble-security [amd64])
Conf liblzma5 (5.6.1+really5.4.5-1ubuntu0.4 Ubuntu:24.04/noble-updates, Ubuntu:24.04/noble-security [amd64])
Inst apt [2.8.3] (2.8.4ubuntu0.1 Ubuntu:24.04/noble-updates, Ubuntu:24.04/noble-security [amd64]) [apt-utils:amd64 ]
Inst libglib2.0-data [2.80.0-6ubuntu3.9] (2.80.0-6ubuntu3.10 Ubuntu:24.04/noble-updates [all])
Inst linux-image-6.8.0-149-generic (6.8.0-149.149 Ubuntu:24.04/noble-updates [amd64])
Inst linux-image-generic [6.8.0-147.147] (6.8.0-149.149 Ubuntu:24.04/noble-updates [amd64])
"""

DNF_CHECK = """\
Upgrades
7zip.x86_64                          26.04-1.fc44               updates
NetworkManager.x86_64                1:1.56.1-2.fc44            updates
kernel-core.x86_64                   7.2.15-200.fc44            updates
tar.x86_64                           2:1.35-9.fc44              updates
Obsoleting packages
    something-old.noarch             1.0-1.fc44                 updates
"""


def test_apt_simulation():
    pending = pkgops.parse_apt_simulation(APT_SIM)
    by = {p["name"]: p for p in pending}
    assert set(by) == {"liblzma5", "apt", "libglib2.0-data", "linux-image-6.8.0-149-generic", "linux-image-generic"}
    assert by["liblzma5"]["is_security"] and by["liblzma5"]["kind"] == "security"
    assert by["liblzma5"]["current"] == "5.6.1+really5.4.5-1ubuntu0.3"
    assert by["liblzma5"]["available"] == "5.6.1+really5.4.5-1ubuntu0.4"
    assert by["apt"]["is_security"]
    assert not by["libglib2.0-data"]["is_security"] and by["libglib2.0-data"]["arch"] == "all"
    assert by["linux-image-6.8.0-149-generic"]["current"] is None
    assert by["linux-image-generic"]["is_kernel"]


def test_dnf_check_upgrade_and_advisories():
    pending = pkgops.parse_dnf_check_upgrade(DNF_CHECK)
    assert [p["name"] for p in pending] == ["7zip", "NetworkManager", "kernel-core", "tar"]
    assert pending[1]["available"] == "1:1.56.1-2.fc44"
    assert pending[2]["is_kernel"]
    pkgops.merge_dnf_advisories(pending, [
        {"name": "FEDORA-1", "type": "bugfix", "severity": "None", "nevra": "tar-2:1.35-9.fc44.x86_64"},
        {"name": "FEDORA-2", "type": "security", "severity": "Moderate", "nevra": "tar-2:1.35-9.fc44.x86_64"},
        {"name": "FEDORA-3", "type": "enhancement", "severity": "None", "nevra": "7zip-26.04-1.fc44.x86_64"},
        {"name": "FEDORA-4", "type": "security", "severity": "Critical",
         "nevra": "NetworkManager-1:1.56.1-2.fc44.x86_64"},
    ])
    by = {p["name"]: p for p in pending}
    assert by["tar"]["is_security"] and by["tar"]["severity"] == "moderate" and by["tar"]["advisory"] == "FEDORA-2"
    assert by["7zip"]["kind"] == "enhancement" and not by["7zip"]["is_security"]
    assert by["NetworkManager"]["severity"] == "critical"
    assert by["kernel-core"]["kind"] == "bugfix"


def test_split_nevra():
    assert pkgops.split_nevra("NetworkManager-1:1.56.1-2.fc44.x86_64") == ("NetworkManager", "1:1.56.1-2.fc44", "x86_64")
    assert pkgops.split_nevra("python3-libs-3.14.0-1.fc44.x86_64") == ("python3-libs", "3.14.0-1.fc44", "x86_64")


def _p(name, sec=False, kernel=False, kind=None, sev=None, current="1", avail="2", arch="amd64"):
    return {"name": name, "arch": arch, "current": current, "available": avail, "is_security": sec,
            "is_kernel": kernel, "kind": kind or ("security" if sec else "bugfix"), "severity": sev}


PENDING = [
    _p("openssl", sec=True, sev="critical"),
    _p("curl", sec=True, sev="low"),
    _p("tzdata", sec=True),                       # Ubuntu: no severity
    _p("linux-image-generic", kernel=True),
    _p("nginx", sec=True, sev="important"),
    _p("htop", kind="enhancement"),
    _p("vim"),
    _p("linux-image-6.8.0-149-generic", kernel=True, current=None),
]


def names(chosen):
    return sorted(p["name"] for p in chosen)


def test_select_kinds_severity_and_exclude():
    chosen, skipped = pkgops.select(PENDING, {"mode": "kinds", "kinds": ["security"], "min_severity": "important",
                                              "exclude": ["nginx"]})
    assert names(chosen) == ["openssl", "tzdata"]
    assert [s["name"] for s in skipped] == ["nginx"]


def test_select_kernel_bugfix_include_and_held():
    chosen, _ = pkgops.select(PENDING, {"mode": "kinds", "kinds": ["kernel", "bugfix"], "include": ["htop"]},
                              held=["vim"])
    assert names(chosen) == ["htop", "linux-image-generic"]


def test_select_all_skips_new_packages():
    chosen, _ = pkgops.select(PENDING, {"mode": "all"})
    assert "linux-image-6.8.0-149-generic" not in names(chosen)
    assert len(chosen) == 7


def test_select_pinned_versions():
    sel = {"mode": "packages", "packages": [{"name": "openssl", "arch": "amd64", "version": "2"},
                                            {"name": "curl", "arch": "amd64", "version": "1.5"}]}
    chosen, skipped = pkgops.select(PENDING, sel)
    assert names(chosen) == ["openssl"]
    assert skipped[0]["name"] == "curl" and "pinned" in skipped[0]["why"]


def test_select_refuses_odd_names():
    with pytest.raises(pkgops.OpError):
        pkgops.select([_p("evil;rm -rf /")], {"mode": "all"})
    with pytest.raises(pkgops.OpError):
        pkgops.select([_p("-oAPT::Foo=1")], {"mode": "all"})
    with pytest.raises(pkgops.OpError):
        pkgops.select([_p("bash", avail="--reinstall")], {"mode": "all"})


def test_select_accepts_real_versions():
    for v in ("38ubuntu0~24.04", "1:1.3.dfsg-3.1ubuntu2.3", "5.6.1+really5.4.5-1ubuntu0.4", "1.2^20260101git-1.fc44"):
        chosen, _ = pkgops.select([_p("pkg", avail=v)], {"mode": "all"})
        assert chosen


def test_next_run_daily_weekly_monthly():
    after = datetime(2026, 11, 9, 1, 30, tzinfo=timezone.utc)  # a Monday
    assert next_run("daily", time(2, 0), after) == datetime(2026, 11, 9, 2, 0, tzinfo=timezone.utc)
    assert next_run("daily", time(1, 0), after) == datetime(2026, 11, 10, 1, 0, tzinfo=timezone.utc)
    assert next_run("weekly", time(3, 0), after, weekdays=[6]) == datetime(2026, 11, 15, 3, 0, tzinfo=timezone.utc)
    assert next_run("monthly", time(1, 0), after, monthday=1) == datetime(2026, 12, 1, 1, 0, tzinfo=timezone.utc)
    # exactly at the time counts as passed
    at = datetime(2026, 11, 9, 2, 0, tzinfo=timezone.utc)
    assert next_run("daily", time(2, 0), at) == datetime(2026, 11, 10, 2, 0, tzinfo=timezone.utc)


def test_describe_policy():
    p = {"repeat": "weekly", "weekdays": [0, 6], "monthday": None, "at_time": time(3, 0), "window_minutes": 90}
    assert describe(p) == "Mon, Sun 03:00, 1.5 h window"


def test_batches():
    assert batches_for(5, 0, False) == [0, 0, 0, 0, 0]
    assert batches_for(5, 2, False) == [0, 0, 1, 1, 2]
    assert batches_for(5, 2, True) == [0, 1, 1, 2, 2]
    assert batches_for(1, 2, True) == [0]
    assert batches_for(0, 2, True) == []


def test_describe_selection():
    assert describe_selection({"mode": "all"}) == "Everything"
    assert describe_selection({"mode": "kinds", "kinds": ["security", "kernel"], "min_severity": "important"}) \
        == "Security, Kernel (important+)"
    assert describe_selection({"mode": "packages", "packages": {"1": [{}, {}], "2": [{}]}}) == "3 picked updates"
    assert describe_selection({"mode": "packages", "packages": [{}]}) == "1 picked update"


def test_parse_host_lines():
    hosts, errors = parse_host_lines("web-01 10.0.0.1\n10.0.0.2:2222\n# comment\nbad name here\nx 1.2.3.4:99999")
    assert hosts == [{"name": "web-01", "address": "10.0.0.1", "port": 22},
                     {"name": "10.0.0.2", "address": "10.0.0.2", "port": 2222}]
    assert len(errors) == 2
