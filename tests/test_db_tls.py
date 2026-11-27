"""Postgres TLS settings: the URL built from the environment, and the three connection paths."""

import asyncio
import os
import subprocess
import sys
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

import pytest
from psycopg.conninfo import conninfo_to_dict

from fleetwright import config, db, gateway, worker

ROOT = Path(__file__).resolve().parent.parent
DEFAULT_URL = "postgresql://fleetwright:fleetwright@db:5432/fleetwright"
TLS_URL = "postgresql://fleetwright:pw@db.example:5432/fleetwright?sslmode=verify-full&sslrootcert=%2Fca.pem"
DB_ENV = ("DATABASE_URL", "POSTGRES_USER", "POSTGRES_PASSWORD", "POSTGRES_HOST", "POSTGRES_PORT",
          "POSTGRES_DB", "FLEETWRIGHT_DB_SSLMODE", "FLEETWRIGHT_DB_SSLROOTCERT")


def fresh_config(**env):
    """Import config.py in a clean process with just these DB settings."""
    clean = {k: v for k, v in os.environ.items() if k not in DB_ENV}
    return subprocess.run([sys.executable, "-c",
                           "from fleetwright.config import DATABASE_URL; print(DATABASE_URL)"],
                          cwd=ROOT, env={**clean, **env}, capture_output=True, text=True)


def query(result):
    return parse_qs(urlsplit(result.stdout.strip()).query)


def test_no_tls_settings_leaves_the_default_url_unchanged():
    result = fresh_config()
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == DEFAULT_URL


def test_explicit_database_url_is_left_alone_without_tls_settings():
    url = "postgresql://u:p@db.example:5432/fw?connect_timeout=5&sslmode=prefer"
    result = fresh_config(DATABASE_URL=url)
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == url


@pytest.mark.parametrize("mode", config.SSL_MODES)
def test_each_libpq_sslmode_is_appended(mode):
    result = fresh_config(FLEETWRIGHT_DB_SSLMODE=mode)
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == f"{DEFAULT_URL}?sslmode={mode}"
    assert query(result) == {"sslmode": [mode]}


def test_sslrootcert_is_appended_and_url_decoded():
    result = fresh_config(FLEETWRIGHT_DB_SSLMODE="verify-full",
                          FLEETWRIGHT_DB_SSLROOTCERT="/etc/fleetwright/db-ca.pem")
    assert result.returncode == 0, result.stderr
    assert query(result) == {"sslmode": ["verify-full"],
                             "sslrootcert": ["/etc/fleetwright/db-ca.pem"]}


def test_existing_query_params_are_kept_and_tls_settings_replace_their_own():
    url = "postgresql://u:p@db.example:5432/fw?application_name=web&sslmode=prefer&connect_timeout=5"
    result = fresh_config(DATABASE_URL=url, FLEETWRIGHT_DB_SSLMODE="verify-full",
                          FLEETWRIGHT_DB_SSLROOTCERT="/ca.pem")
    assert result.returncode == 0, result.stderr
    parts = urlsplit(result.stdout.strip())
    assert (parts.scheme, parts.netloc, parts.path) == ("postgresql", "u:p@db.example:5432", "/fw")
    assert query(result) == {"application_name": ["web"], "connect_timeout": ["5"],
                             "sslmode": ["verify-full"], "sslrootcert": ["/ca.pem"]}


def test_sslrootcert_alone_keeps_the_sslmode_from_an_explicit_url():
    url = "postgresql://u:p@db.example:5432/fw?sslmode=verify-full"
    result = fresh_config(DATABASE_URL=url, FLEETWRIGHT_DB_SSLROOTCERT="/ca.pem")
    assert result.returncode == 0, result.stderr
    assert query(result) == {"sslmode": ["verify-full"], "sslrootcert": ["/ca.pem"]}


def test_remote_postgres_parts_still_build_the_url_with_tls():
    result = fresh_config(POSTGRES_HOST="db.example", POSTGRES_PORT="6543", POSTGRES_USER="fw",
                          POSTGRES_PASSWORD="pw", POSTGRES_DB="fwdb",
                          FLEETWRIGHT_DB_SSLMODE="require")
    assert result.returncode == 0, result.stderr
    parts = urlsplit(result.stdout.strip())
    assert (parts.scheme, parts.netloc, parts.path) == ("postgresql", "fw:pw@db.example:6543", "/fwdb")
    assert query(result) == {"sslmode": ["require"]}


def test_an_invalid_sslmode_fails_with_the_allowed_values():
    result = fresh_config(FLEETWRIGHT_DB_SSLMODE="required")
    assert result.returncode != 0
    assert "not a libpq sslmode" in result.stderr
    assert all(mode in result.stderr for mode in config.SSL_MODES)


def test_psycopg_reads_the_tls_settings_from_the_url():
    # No connection is made here: libpq must still decode the URL's query params.
    assert conninfo_to_dict(TLS_URL) == {
        "user": "fleetwright", "password": "pw", "dbname": "fleetwright", "host": "db.example",
        "port": "5432", "sslmode": "verify-full", "sslrootcert": "/ca.pem"}


def test_the_pool_connects_with_the_configured_url(monkeypatch):
    seen = []

    class FakePool:
        def __init__(self, url, **kwargs):
            seen.append(url)

        async def open(self, **kwargs):
            pass

    monkeypatch.setattr(config, "DATABASE_URL", TLS_URL)
    monkeypatch.setattr(db, "_pool", None)
    monkeypatch.setattr(db, "AsyncConnectionPool", FakePool)
    asyncio.run(db.open_pool())
    assert seen == [TLS_URL]


@pytest.mark.parametrize("connect", [gateway.listener, lambda: worker.Worker().listen()],
                         ids=["gateway", "worker"])
def test_both_notify_listeners_connect_with_the_configured_url(connect, monkeypatch):
    seen = []

    async def fake_connect(url, **kwargs):
        seen.append(url)
        raise asyncio.CancelledError       # stop the retry loop after the first attempt

    monkeypatch.setattr(config, "DATABASE_URL", TLS_URL)
    monkeypatch.setattr(gateway.psycopg.AsyncConnection, "connect", fake_connect)
    with pytest.raises(asyncio.CancelledError):
        asyncio.run(connect())
    assert seen == [TLS_URL]
