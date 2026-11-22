#!/usr/bin/env python3
"""apt-get, dpkg-query and apt-mark for the SSH farm: answers the way pkgops expects,
from fakepkgs, with no real packages. FW_SEED (set per sshd) picks the host."""
import os
import random
import sys
import time

sys.path.insert(0, "/opt/fake")
import fakepkgs  # noqa: E402

seed = int(os.environ.get("FW_SEED", "0"))
state = f"/var/lib/fakeapt/{seed}"


def applied() -> set:
    try:
        with open(state) as f:
            return {l.strip() for l in f if l.strip()}
    except OSError:
        return set()


prog, args = os.path.basename(sys.argv[0]), sys.argv[1:]
installed, pending = fakepkgs.host(seed, applied())
if prog == "dpkg-query":
    for name, ver in installed.items():
        print(f"{name}:amd64 {ver} ii ")
elif prog == "apt-mark":
    pass
elif prog == "apt-get" and "update" in args:
    time.sleep(random.uniform(0.5, 2))
    print("Hit:1 http://archive.ubuntu.com/ubuntu noble InRelease\nReading package lists...")
elif prog == "apt-get" and "-s" in args:
    print("Reading package lists...\nBuilding dependency tree...")
    for p in pending:
        print(f"Inst {p['name']} [{p['current']}] ({p['available']} Ubuntu:24.04/{p['source']} [amd64])")
elif prog == "apt-get" and "install" in args:
    names = [a.split("=")[0].split(":")[0] for a in args if "=" in a and not a.startswith("-") and "::" not in a]
    time.sleep(random.uniform(2, 5))
    os.makedirs(os.path.dirname(state), exist_ok=True)
    with open(state, "a") as f:
        for n in names:
            print(f"Setting up {n} (1.0-1ubuntu2) ...")
            f.write(n + "\n")
else:
    print(f"fakeapt: unexpected {prog} {args}", file=sys.stderr)
    sys.exit(1)
