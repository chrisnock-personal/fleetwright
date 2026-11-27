"""Settings from the environment (.env in compose)."""

from __future__ import annotations

import os
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

# libpq's sslmode values, in the order its docs list them.
SSL_MODES = ("disable", "allow", "prefer", "require", "verify-ca", "verify-full")


def _int(name: str, default: int) -> int:
    try:
        return int(os.getenv(name, default))
    except ValueError:
        return default


def _database_url() -> str:
    """The URL every DB connection uses. Explicit TLS settings are appended to it.

    With neither FLEETWRIGHT_DB_SSLMODE nor FLEETWRIGHT_DB_SSLROOTCERT set, the
    URL is returned exactly as configured, so the local compose database keeps
    working as before. A DATABASE_URL supplied by the operator wins over the
    POSTGRES_* parts; the TLS settings override sslmode/sslrootcert already in
    its query string rather than adding a second copy of either.
    """
    url = os.getenv(
        "DATABASE_URL",
        "postgresql://{u}:{p}@{h}:{port}/{d}".format(
            u=os.getenv("POSTGRES_USER", "fleetwright"),
            p=os.getenv("POSTGRES_PASSWORD", "fleetwright"),
            h=os.getenv("POSTGRES_HOST", "db"),
            port=os.getenv("POSTGRES_PORT", "5432"),
            d=os.getenv("POSTGRES_DB", "fleetwright"),
        ),
    )
    sslmode = os.getenv("FLEETWRIGHT_DB_SSLMODE", "").strip().lower()
    sslrootcert = os.getenv("FLEETWRIGHT_DB_SSLROOTCERT", "").strip()
    if not sslmode and not sslrootcert:
        return url
    if sslmode and sslmode not in SSL_MODES:
        raise ValueError(
            f"FLEETWRIGHT_DB_SSLMODE={sslmode!r} is not a libpq sslmode; "
            f"use one of {', '.join(SSL_MODES)}")
    changes = {}
    if sslmode:
        changes["sslmode"] = sslmode
    if sslrootcert:
        changes["sslrootcert"] = sslrootcert
    parts = urlsplit(url)
    query = [(k, v) for k, v in parse_qsl(parts.query, keep_blank_values=True) if k not in changes]
    query.extend(changes.items())
    return urlunsplit(parts._replace(query=urlencode(query)))


DATABASE_URL = _database_url()
SECRET_KEY = os.getenv("FLEETWRIGHT_SECRET_KEY", "")
# Earlier secret keys, comma-separated, while rotating: stored secrets encrypted under
# one of these still decrypt, and are re-encrypted under SECRET_KEY at startup.
SECRET_KEY_PREVIOUS = [k.strip() for k in os.getenv("FLEETWRIGHT_SECRET_KEY_PREVIOUS", "").split(",") if k.strip()]
# HTTPS is on by default (self-signed on first start; upload your own under Settings).
# "off" serves plain HTTP for running behind a TLS proxy.
TLS_ON = os.getenv("FLEETWRIGHT_TLS", "on").lower() not in ("0", "off", "false", "no")
TLS_DIR = os.getenv("FLEETWRIGHT_TLS_DIR", "/data/certs")
# Extra names and IPs for the self-signed certificate, comma-separated.
TLS_NAMES = os.getenv("FLEETWRIGHT_TLS_NAMES", "")
# The address agents and install commands use to reach this server.
PUBLIC_URL = os.getenv("FLEETWRIGHT_PUBLIC_URL",
                       "https://127.0.0.1:8443" if TLS_ON else "http://127.0.0.1:8080").rstrip("/")
# Session cookies over HTTPS only: on whenever FleetWright serves HTTPS, or a proxy in front does.
SECURE_COOKIES = os.getenv("FLEETWRIGHT_SECURE_COOKIES", "true" if TLS_ON else "false").lower() \
    in ("1", "true", "yes")

# API: requests a minute per token (bursts of up to 120 are fine)
API_RATE_PER_MIN = _int("FLEETWRIGHT_API_RATE_PER_MIN", 600)

# Worker
WORKER_NAME = os.getenv("FLEETWRIGHT_WORKER_NAME", "") or f"worker-{os.getpid()}"
SSH_CONCURRENCY = _int("FLEETWRIGHT_SSH_CONCURRENCY", 50)
SSH_CONNECT_TIMEOUT = _int("FLEETWRIGHT_SSH_CONNECT_TIMEOUT", 15)
TASK_TIMEOUT = _int("FLEETWRIGHT_TASK_TIMEOUT", 3600)
SCAN_INTERVAL_MIN = _int("FLEETWRIGHT_SCAN_INTERVAL_MIN", 360)
REBOOT_WAIT = _int("FLEETWRIGHT_REBOOT_WAIT", 600)
LOG_RETENTION_DAYS = _int("FLEETWRIGHT_LOG_RETENTION_DAYS", 90)
