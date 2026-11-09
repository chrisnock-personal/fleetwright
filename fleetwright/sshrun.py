"""
sshrun.py
~~~~~~~~~
Running pkgops on an agentless host: connect with the stored key, pipe
pkgops.py to ``sudo -n python3 -``, stream its output back.

Host keys: the first connection to a host pins the key it offers (trust on
first use, like answering "yes" to ssh's prompt). Every later connection
passes only that key to the SSH handshake, so a host offering a different key
is refused during key exchange, before FleetWright authenticates or sends
anything. "Forget pinned host key" on the host page clears it after a
deliberate rebuild.
"""

from __future__ import annotations

import asyncio
import json
import shlex
from pathlib import Path
from typing import Awaitable, Callable, Optional

import asyncssh

from . import config, db, security
from .pkgops import RESULT_PREFIX

PKGOPS_SOURCE = (Path(__file__).parent / "pkgops.py").read_text()

LineSink = Callable[[str], Awaitable[None]]


class HostKeyMismatch(Exception):
    pass


class SSHFailure(Exception):
    pass


async def _credential(host: dict) -> dict:
    if not host.get("credential_id"):
        raise SSHFailure("No SSH key is set for this host")
    cred = await db.fetchone("SELECT * FROM ssh_credentials WHERE id = %s", host["credential_id"])
    if not cred:
        raise SSHFailure("This host's SSH key was deleted")
    return cred


async def connect(host: dict) -> asyncssh.SSHClientConnection:
    cred = await _credential(host)
    key = asyncssh.import_private_key(security.decrypt(cred["private_key_enc"]))
    pinned = host.get("ssh_host_key")
    # (trusted host keys, trusted CA keys, revoked keys): only the pinned key is accepted.
    known = ([asyncssh.import_public_key(pinned)], [], []) if pinned else None
    try:
        conn = await asyncio.wait_for(asyncssh.connect(
            host["address"], port=host["port"], username=cred["username"], client_keys=[key],
            known_hosts=known, agent_path=None, password=None, kbdint_auth=False,
            connect_timeout=config.SSH_CONNECT_TIMEOUT, keepalive_interval=30),
            timeout=config.SSH_CONNECT_TIMEOUT + 5)
    except asyncssh.HostKeyNotVerifiable as e:
        raise HostKeyMismatch(
            "The host offered a different SSH host key from the one pinned when FleetWright first "
            "connected, so nothing was sent. If the host was rebuilt, use “Forget pinned host key” "
            "on its page; otherwise investigate.") from e
    except (OSError, asyncssh.Error, asyncio.TimeoutError) as e:
        raise SSHFailure(f"Can't connect to {host['address']}:{host['port']}: {e or type(e).__name__}") from e
    seen = conn.get_server_host_key().export_public_key().decode().strip()
    if not pinned:
        await db.execute("UPDATE hosts SET ssh_host_key = %s WHERE id = %s AND ssh_host_key IS NULL",
                         seen, host["id"])
    return conn


async def run_pkgops(host: dict, op: str, arg: Optional[dict], on_line: LineSink,
                     conn: Optional[asyncssh.SSHClientConnection] = None) -> dict:
    """Run one pkgops operation; returns its result dict (ok False on failure)."""
    own = conn is None
    conn = conn or await connect(host)
    try:
        cred_user = (await _credential(host))["username"]
        cmd = ["python3", "-", op] + ([json.dumps(arg)] if arg is not None else [])
        line = " ".join(shlex.quote(c) for c in cmd)
        if cred_user != "root":
            line = "sudo -n " + line
        result: Optional[dict] = None
        async with conn.create_process(line, stderr=asyncssh.STDOUT) as proc:
            proc.stdin.write(PKGOPS_SOURCE)
            proc.stdin.write_eof()
            async for raw in proc.stdout:
                text = raw.rstrip("\n")
                if text.startswith(RESULT_PREFIX):
                    try:
                        result = json.loads(text[len(RESULT_PREFIX):])
                    except ValueError:
                        result = {"ok": False, "error": "unreadable result from host"}
                else:
                    await on_line(text)
            await proc.wait()
        if result is None:
            hint = ""
            if cred_user != "root":
                hint = (" The SSH user needs passwordless sudo for python3 "
                        "(see docs/agentless.md).")
            return {"ok": False, "error": f"No result from the host (exit {proc.exit_status}).{hint}"}
        return result
    finally:
        if own:
            conn.close()


async def boot_id(host: dict) -> Optional[str]:
    try:
        conn = await connect(host)
    except (SSHFailure, HostKeyMismatch):
        return None
    try:
        res = await conn.run("cat /proc/sys/kernel/random/boot_id", check=False, timeout=15)
        return (res.stdout or "").strip() or None
    except (asyncssh.Error, OSError, asyncio.TimeoutError):
        return None
    finally:
        conn.close()
