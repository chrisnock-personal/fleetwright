"""
fakepkgs.py
~~~~~~~~~~~
Made-up but stable package data for load-test hosts. A host is a seed: the same
seed always has the same packages and pending updates, minus whatever has been
applied since. Used by the simulated agents and by the fake apt in the SSH farm.

Standard library only (it runs inside the SSH farm's Alpine container too).
"""

from __future__ import annotations

import random

POOL = 400                 # installed packages per host
KERNEL = {"linux-image-generic", "linux-headers-generic", "linux-modules-6.8.0-50-generic"}


def names() -> list[str]:
    base = [f"pkg-{i:04d}" for i in range(POOL - len(KERNEL) - 3)]
    return base + sorted(KERNEL) + ["openssl", "libssl3t64", "openssh-server"]


def host(seed: int, applied: set[str] = frozenset(), max_pending: int = 150) -> tuple[dict, list[dict]]:
    """(installed {name: version}, pending updates in pkgops' scan format)."""
    rng = random.Random(seed)
    pkgs = names()
    n = rng.randint(0, max_pending)
    waiting = set(rng.sample(pkgs, n))
    installed, pending = {}, []
    for name in pkgs:
        old, new = "1.0-1ubuntu1", "1.0-1ubuntu2"
        security = rng.random() < 0.15
        if name not in waiting or name in applied:
            installed[name] = new if name in waiting else old
            continue
        installed[name] = old
        pocket = "noble-security" if security else "noble-updates"
        pending.append({"name": name, "arch": "amd64", "current": old, "available": new,
                        "source": pocket, "is_security": security, "is_kernel": name in KERNEL,
                        "kind": "security" if security else "bugfix", "severity": None, "advisory": None})
    return installed, pending
