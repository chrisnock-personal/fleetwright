"""
db.py
~~~~~
Postgres access (psycopg 3, async). One pool per process.

The schema lives in schema.sql and is applied at start when it has changed
(its SHA-256 is kept in settings); every statement in it is idempotent. Postgres is also the job queue: workers
claim tasks with ``FOR UPDATE SKIP LOCKED`` and are woken by NOTIFY.
"""

from __future__ import annotations

import hashlib
import logging
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any, Optional

from psycopg.rows import dict_row
from psycopg.types.json import Jsonb
from psycopg_pool import AsyncConnectionPool

from . import config

log = logging.getLogger("fleetwright.db")

_pool: Optional[AsyncConnectionPool] = None


async def open_pool(min_size: int = 1, max_size: int = 10) -> AsyncConnectionPool:
    global _pool
    if _pool is None:
        # jit=off: FleetWright's queries are short, and JIT compiling them cost more than
        # running them (the load test's package search: 104 ms with JIT, 8 ms without).
        _pool = AsyncConnectionPool(config.DATABASE_URL, min_size=min_size, max_size=max_size,
                                    kwargs={"row_factory": dict_row, "autocommit": True,
                                            "options": "-c jit=off"},
                                    open=False)
        await _pool.open(wait=True, timeout=60)
    return _pool


async def close_pool() -> None:
    global _pool
    if _pool is not None:
        await _pool.close()
        _pool = None


def pool() -> AsyncConnectionPool:
    if _pool is None:
        raise RuntimeError("database pool not opened")
    return _pool


async def migrate() -> None:
    """Apply schema.sql, unless this exact version already is. The web process and the
    worker both call this at start: the second must not rerun the DDL while the first is
    already working, or its table locks deadlock with the worker claiming tasks."""
    sql = (Path(__file__).parent / "schema.sql").read_text()
    digest = hashlib.sha256(sql.encode()).hexdigest()
    async with pool().connection() as conn:
        # Two processes starting together must not both run the DDL.
        await conn.execute("SELECT pg_advisory_lock(42424242)")
        try:
            have = None
            if (await (await conn.execute("SELECT to_regclass('settings') IS NOT NULL AS ok")).fetchone())["ok"]:
                row = await (await conn.execute(
                    "SELECT value FROM settings WHERE key = 'schema_sha256'")).fetchone()
                have = row["value"] if row else None
            if have == digest:
                log.info("schema up to date (unchanged)")
                return
            await conn.execute(sql)
            await conn.execute("""INSERT INTO settings (key, value) VALUES ('schema_sha256', %s)
                                  ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value""", (digest,))
        finally:
            await conn.execute("SELECT pg_advisory_unlock(42424242)")
    log.info("schema applied")


@asynccontextmanager
async def transaction():
    async with pool().connection() as conn:
        async with conn.transaction():
            yield conn


async def fetch(sql: str, *args: Any) -> list[dict]:
    async with pool().connection() as conn:
        cur = await conn.execute(sql, args or None)
        return await cur.fetchall()


async def fetchone(sql: str, *args: Any) -> Optional[dict]:
    async with pool().connection() as conn:
        cur = await conn.execute(sql, args or None)
        return await cur.fetchone()


async def fetchval(sql: str, *args: Any) -> Any:
    row = await fetchone(sql, *args)
    return None if row is None else next(iter(row.values()))


async def execute(sql: str, *args: Any) -> int:
    async with pool().connection() as conn:
        cur = await conn.execute(sql, args or None)
        return cur.rowcount


async def notify(channel: str, payload: str = "") -> None:
    await execute("SELECT pg_notify(%s, %s)", channel, payload)


async def audit(actor: str, what: str) -> None:
    await execute("INSERT INTO audit_log (actor, what) VALUES (%s, %s)", actor, what)


def J(value: Any) -> Jsonb:
    return Jsonb(value)
