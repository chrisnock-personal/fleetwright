"""Settings from the environment (.env in compose)."""

from __future__ import annotations

import os


def _int(name: str, default: int) -> int:
    try:
        return int(os.getenv(name, default))
    except ValueError:
        return default


DATABASE_URL = os.getenv(
    "DATABASE_URL",
    "postgresql://{u}:{p}@{h}:{port}/{d}".format(
        u=os.getenv("POSTGRES_USER", "fleetwright"),
        p=os.getenv("POSTGRES_PASSWORD", "fleetwright"),
        h=os.getenv("POSTGRES_HOST", "db"),
        port=os.getenv("POSTGRES_PORT", "5432"),
        d=os.getenv("POSTGRES_DB", "fleetwright"),
    ),
)
SECRET_KEY = os.getenv("FLEETWRIGHT_SECRET_KEY", "")
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

# Worker
WORKER_NAME = os.getenv("FLEETWRIGHT_WORKER_NAME", "") or f"worker-{os.getpid()}"
SSH_CONCURRENCY = _int("FLEETWRIGHT_SSH_CONCURRENCY", 50)
SSH_CONNECT_TIMEOUT = _int("FLEETWRIGHT_SSH_CONNECT_TIMEOUT", 15)
TASK_TIMEOUT = _int("FLEETWRIGHT_TASK_TIMEOUT", 3600)
SCAN_INTERVAL_MIN = _int("FLEETWRIGHT_SCAN_INTERVAL_MIN", 360)
REBOOT_WAIT = _int("FLEETWRIGHT_REBOOT_WAIT", 600)
LOG_RETENTION_DAYS = _int("FLEETWRIGHT_LOG_RETENTION_DAYS", 90)
