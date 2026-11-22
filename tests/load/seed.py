"""
seed.py
~~~~~~~
Sets up a fresh FleetWright database for a load test. Runs in the FleetWright
image on the compose network, with its .env (it needs the database and the
secret key; see README.md):

    python /load/seed.py base                      admin, enrolment token, SSH key, a policy
    python /load/seed.py ssh 300 sshfarm 2200      300 SSH hosts at sshfarm:2200..2499
    python /load/seed.py synthetic 5000            5000 hosts with pending updates straight
                                                   into the database (never scanned: no SSH key)

`base` prints the enrolment token and the public key for the SSH farm.
"""

from __future__ import annotations

import asyncio
import random
import sys
import uuid

import asyncssh

sys.path[:0] = ["/app", "/load"]
import fakepkgs  # noqa: E402
from fleetwright import db, fleet, security  # noqa: E402

ADMIN = ("load@test.local", "Load-test-pass-1")
TOKEN = "load-test-enrol"


async def base() -> None:
    await db.execute("""INSERT INTO users (email, name, role, password_hash) VALUES (%s, 'Load test', 'admin', %s)
                        ON CONFLICT (email) DO NOTHING""", ADMIN[0], security.hash_password(ADMIN[1]))
    await db.execute("""INSERT INTO enroll_tokens (token_hash, label, expires_at, created_by)
                        VALUES (%s, 'load test', NOW() + INTERVAL '7 days', 'seed')
                        ON CONFLICT (token_hash) DO NOTHING""", security.token_hash(TOKEN))
    pub = await db.fetchval("SELECT public_key FROM ssh_credentials WHERE name = 'load'")
    if not pub:
        key = asyncssh.generate_private_key("ssh-ed25519")
        pub = key.export_public_key().decode().strip() + " fleetwright-load"
        await db.execute("""INSERT INTO ssh_credentials (name, username, private_key_enc, public_key)
                            VALUES ('load', 'root', %s, %s)""", security.encrypt(key.export_private_key().decode()), pub)
    await db.execute("""INSERT INTO policies (name, enabled, target, selection, created_by)
                        VALUES ('Load: security, all hosts', FALSE, '{"all": true}',
                                '{"mode": "kinds", "kinds": ["security", "kernel"]}', 'seed')
                        ON CONFLICT (name) DO NOTHING""")
    print(f"admin      {ADMIN[0]} / {ADMIN[1]}")
    print(f"token      {TOKEN}")
    print(f"public key {pub}")


async def ssh(count: int, address: str, first_port: int) -> None:
    cred = await db.fetchval("SELECT id FROM ssh_credentials WHERE name = 'load'")
    groups = await _groups()
    for i in range(count):
        await db.execute("""INSERT INTO hosts (name, address, port, mode, credential_id, group_id, tags)
                            VALUES (%s, %s, %s, 'ssh', %s, %s, %s) ON CONFLICT (name) DO NOTHING""",
                         f"load-ssh-{i:04d}", address, first_port + i, cred, random.choice(groups),
                         [random.choice(["web", "db", "cache", "batch"])])
    ids = [r["id"] for r in await db.fetch("SELECT id FROM hosts WHERE name LIKE 'load-ssh-%'")]
    print(f"{len(ids)} SSH hosts; queued {await fleet.queue_scan(ids)} scans")


async def synthetic(count: int) -> None:
    groups = await _groups()
    have = await db.fetchval("SELECT COUNT(*) FROM hosts WHERE name LIKE 'synth-%'")
    for start in range(have, have + count, 500):
        rows, pend = [], []
        for i in range(start, min(start + 500, have + count)):
            _, pending = fakepkgs.host(500_000 + i)
            rows.append((f"synth-{i:05d}", f"10.200.{i // 250}.{i % 250 + 1}", random.choice(groups),
                         [random.choice(["web", "db", "cache", "batch"])], len(pending),
                         sum(p["is_security"] for p in pending), random.random() < 0.1, uuid.uuid4().hex))
            pend.append(pending)
        async with db.transaction() as conn:
            ids = []
            for r in rows:
                cur = await conn.execute(
                    """INSERT INTO hosts (name, address, mode, group_id, tags, pending_count, security_count,
                                          reboot_required, machine_id, os_id, os_version, os_pretty, pkg_family,
                                          kernel, last_scan_at, last_seen, auto_updates)
                       VALUES (%s,%s,'ssh',%s,%s,%s,%s,%s,%s,'ubuntu','24.04','Ubuntu 24.04.1 LTS (synthetic)',
                               'apt','6.8.0-49-generic',NOW(),NOW(),'[]') RETURNING id""", r)
                ids.append((await cur.fetchone())["id"])
            async with conn.cursor() as cur:
                async with cur.copy("""COPY pending_updates (host_id, name, arch, current, available, source,
                                       is_security, is_kernel, kind) FROM STDIN""") as copy:
                    for hid, pending in zip(ids, pend):
                        for p in pending:
                            await copy.write_row((hid, p["name"], p["arch"], p["current"], p["available"],
                                                  p["source"], p["is_security"], p["is_kernel"], p["kind"]))
        print(f"  {min(start + 500, have + count)} synthetic hosts", flush=True)


async def _groups() -> list[int]:
    for g in ("london", "dublin", "frankfurt", "virginia", "oregon", "singapore"):
        await db.execute("INSERT INTO groups (name) VALUES (%s) ON CONFLICT DO NOTHING", f"load-{g}")
    return [r["id"] for r in await db.fetch("SELECT id FROM groups WHERE name LIKE 'load-%'")]


async def main(argv: list[str]) -> None:
    await db.open_pool()
    if argv[0] == "base":
        await base()
    elif argv[0] == "ssh":
        await ssh(int(argv[1]), argv[2], int(argv[3]))
    elif argv[0] == "synthetic":
        await synthetic(int(argv[1]))
    else:
        print(__doc__)
    await db.close_pool()


if __name__ == "__main__":
    asyncio.run(main(sys.argv[1:]))
