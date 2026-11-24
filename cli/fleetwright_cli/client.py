"""
The HTTP side of fw: profiles, tokens, certificate pinning and the API calls.
Standard library only, so `pipx install` needs nothing else (the OS keyring is
used when the `keyring` package happens to be installed).
"""

from __future__ import annotations

import hashlib
import http.client
import json
import os
import ssl
import stat
import urllib.parse
from pathlib import Path
from typing import Any, Iterator, Optional

CONFIG = Path(os.environ.get("FW_CONFIG") or Path(os.environ.get("XDG_CONFIG_HOME") or Path.home() / ".config")
              / "fleetwright" / "cli.json")
KEYRING_SERVICE = "fleetwright-cli"

# Exit codes (stable: scripts and agents rely on them)
OK, FAILED, USAGE, NOT_ALLOWED, NOT_FOUND = 0, 1, 2, 3, 4


class CLIError(Exception):
    def __init__(self, message: str, code: int = FAILED, details: Optional[list] = None):
        super().__init__(message)
        self.message, self.code, self.details = message, code, details or []


# ─── Profiles ───────────────────────────────────────────────────────────────

def load_config() -> dict:
    try:
        return json.loads(CONFIG.read_text())
    except FileNotFoundError:
        return {"default": None, "profiles": {}}
    except ValueError as e:
        raise CLIError(f"{CONFIG} isn't valid JSON: {e}") from e


def save_config(cfg: dict) -> None:
    CONFIG.parent.mkdir(parents=True, exist_ok=True)
    tmp = CONFIG.with_suffix(".tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        json.dump(cfg, f, indent=1)
    os.replace(tmp, CONFIG)


def _keyring():
    try:
        import keyring  # type: ignore
        return keyring
    except Exception:  # noqa: BLE001 - optional
        return None


def store_token(profile: str, token: str, cfg: dict) -> str:
    """Keep a profile's token in the OS keyring if there is one, else in the config file (mode 600)."""
    kr = _keyring()
    if kr:
        try:
            kr.set_password(KEYRING_SERVICE, profile, token)
            cfg["profiles"][profile].pop("token", None)
            return "the OS keyring"
        except Exception:  # noqa: BLE001 - no usable backend
            pass
    cfg["profiles"][profile]["token"] = token
    return f"{CONFIG} (readable only by you)"


def forget_token(profile: str, cfg: dict) -> None:
    kr = _keyring()
    if kr:
        try:
            kr.delete_password(KEYRING_SERVICE, profile)
        except Exception:  # noqa: BLE001
            pass
    cfg["profiles"].get(profile, {}).pop("token", None)


def resolve_profile(name: Optional[str]) -> tuple[str, dict, str]:
    """(profile name, its settings, its token). FW_URL and FW_TOKEN override a profile, and
    work with no config at all (handy in CI)."""
    cfg = load_config()
    name = name or os.environ.get("FW_PROFILE") or cfg.get("default")
    prof = dict(cfg["profiles"].get(name or "", {}))
    if os.environ.get("FW_URL"):
        prof["url"] = os.environ["FW_URL"]
    if os.environ.get("FW_FINGERPRINT"):
        prof["fingerprint"] = os.environ["FW_FINGERPRINT"]
    if not prof.get("url"):
        raise CLIError("No server configured: run `fw login --url https://your-fleetwright:8443`, "
                       "or set FW_URL and FW_TOKEN.", USAGE)
    token = os.environ.get("FW_TOKEN") or prof.get("token")
    if not token and name:
        kr = _keyring()
        if kr:
            try:
                token = kr.get_password(KEYRING_SERVICE, name)
            except Exception:  # noqa: BLE001
                token = None
    if not token:
        raise CLIError(f"No API token for profile {name or '(none)'}: run `fw login`, or set FW_TOKEN.", USAGE)
    if CONFIG.exists() and prof.get("token") and CONFIG.stat().st_mode & (stat.S_IRWXG | stat.S_IRWXO):
        raise CLIError(f"{CONFIG} holds a token but others can read it: chmod 600 {CONFIG}", NOT_ALLOWED)
    return name or "", prof, token


# ─── Talking to the server ──────────────────────────────────────────────────

def fingerprint_of(der: bytes) -> str:
    """SHA-256 of the certificate, as FleetWright's Settings → HTTPS page shows it."""
    h = hashlib.sha256(der).hexdigest().upper()
    return ":".join(h[i:i + 2] for i in range(0, len(h), 2))


def server_certificate(url: str) -> tuple[bytes, bool]:
    """The server's certificate (DER), and whether the system CAs trust it."""
    u = urllib.parse.urlsplit(url)
    host, port = u.hostname, u.port or 443
    try:
        conn = http.client.HTTPSConnection(host, port, timeout=15, context=ssl.create_default_context())
        conn.connect()
        der = conn.sock.getpeercert(binary_form=True)
        conn.close()
        return der, True
    except ssl.SSLCertVerificationError:
        pass
    ctx = ssl.create_default_context()
    ctx.check_hostname, ctx.verify_mode = False, ssl.CERT_NONE
    conn = http.client.HTTPSConnection(host, port, timeout=15, context=ctx)
    conn.connect()
    der = conn.sock.getpeercert(binary_form=True)
    conn.close()
    return der, False


class Client:
    def __init__(self, url: str, token: str, fingerprint: Optional[str] = None, timeout: float = 60):
        u = urllib.parse.urlsplit(url.rstrip("/"))
        if u.scheme not in ("https", "http"):
            raise CLIError(f"The server URL must start with https:// ({url})", USAGE)
        self.scheme, self.host, self.port = u.scheme, u.hostname, u.port or (443 if u.scheme == "https" else 80)
        self.base = (u.path or "") + "/api/v1"
        self.token, self.fingerprint, self.timeout = token, fingerprint, timeout

    def _connect(self, timeout: Optional[float] = None) -> http.client.HTTPConnection:
        t = self.timeout if timeout is None else timeout
        if self.scheme == "http":
            return http.client.HTTPConnection(self.host, self.port, timeout=t)
        if self.fingerprint:
            # Pinned: only this exact certificate, checked before the token is sent.
            ctx = ssl.create_default_context()
            ctx.check_hostname, ctx.verify_mode = False, ssl.CERT_NONE
        else:
            ctx = ssl.create_default_context()
        conn = http.client.HTTPSConnection(self.host, self.port, timeout=t, context=ctx)
        try:
            conn.connect()
        except ssl.SSLCertVerificationError as e:
            raise CLIError(f"The server's certificate isn't trusted ({e.verify_message}). If it's FleetWright's "
                           "self-signed one, run `fw login` to pin it.", NOT_ALLOWED) from e
        except OSError as e:
            raise CLIError(f"Can't reach {self.host}:{self.port}: {e}") from e
        if self.fingerprint:
            got = fingerprint_of(conn.sock.getpeercert(binary_form=True))
            if got.replace(":", "") != self.fingerprint.replace(":", "").upper():
                conn.close()
                raise CLIError(f"The server's certificate has changed (now {got}). Nothing was sent. If that's "
                               "expected (check Settings → HTTPS), run `fw login` again.", NOT_ALLOWED)
        return conn

    def _headers(self, extra: Optional[dict] = None) -> dict:
        return {"Authorization": f"Bearer {self.token}", "Accept": "application/json",
                "User-Agent": "fleetwright-cli", **(extra or {})}

    def request(self, method: str, path: str, body: Any = None, params: Optional[dict] = None,
                headers: Optional[dict] = None) -> Any:
        q = {k: v for k, v in (params or {}).items() if v is not None and v != ""}
        target = self.base + path + ("?" + urllib.parse.urlencode(q, doseq=True) if q else "")
        hdrs = self._headers(headers)
        data = None
        if body is not None:
            data = json.dumps(body).encode()
            hdrs["Content-Type"] = "application/json"
        conn = self._connect()
        try:
            conn.request(method, target, body=data, headers=hdrs)
            resp = conn.getresponse()
            raw = resp.read()
        except OSError as e:
            raise CLIError(f"The request to {self.host} failed: {e}") from e
        finally:
            conn.close()
        try:
            payload = json.loads(raw) if raw else None
        except ValueError:
            payload = raw.decode(errors="replace")
        if resp.status >= 400:
            err = payload.get("error", {}) if isinstance(payload, dict) else {}
            msg = err.get("message") or f"HTTP {resp.status}"
            code = {400: USAGE, 401: NOT_ALLOWED, 403: NOT_ALLOWED, 404: NOT_FOUND}.get(resp.status, FAILED)
            if resp.status == 429:
                msg += f" (retry after {resp.getheader('Retry-After', '?')} s)"
            raise CLIError(msg, code, err.get("errors"))
        return payload

    def get(self, path, **params):
        return self.request("GET", path, params=params)

    def post(self, path, body=None, headers=None):
        return self.request("POST", path, body if body is not None else {}, headers=headers)

    def pages(self, path: str, key: str, limit: int = 500, **params) -> Iterator[dict]:
        """Every item of a cursor-paged list."""
        cursor = None
        while True:
            page = self.get(path, limit=limit, cursor=cursor, **params)
            yield from page[key]
            cursor = page.get("next_cursor")
            if not cursor:
                return

    def events(self, path: str) -> Iterator[tuple[str, Any]]:
        """Server-Sent Events from a streaming endpoint, as (event, data)."""
        conn = self._connect(timeout=120)
        try:
            conn.request("GET", self.base + path, headers=self._headers({"Accept": "text/event-stream"}))
            resp = conn.getresponse()
            if resp.status >= 400:
                raw = resp.read()
                try:
                    err = json.loads(raw).get("error", {})
                except ValueError:
                    err = {}
                raise CLIError(err.get("message") or f"HTTP {resp.status}",
                               {401: NOT_ALLOWED, 403: NOT_ALLOWED, 404: NOT_FOUND}.get(resp.status, FAILED))
            event, data = None, []
            while True:
                line = resp.readline()
                if not line:
                    return
                line = line.decode("utf-8", "replace").rstrip("\r\n")
                if line.startswith("event:"):
                    event = line[6:].strip()
                elif line.startswith("data:"):
                    data.append(line[5:].strip())
                elif not line and event:
                    yield event, json.loads("\n".join(data)) if data else None
                    if event == "end":
                        return
                    event, data = None, []
        finally:
            conn.close()
