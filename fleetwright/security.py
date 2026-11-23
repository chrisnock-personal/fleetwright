"""Encryption of stored secrets, password hashing and tokens."""

from __future__ import annotations

import base64
import hashlib
import secrets

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError
from cryptography.fernet import Fernet, InvalidToken, MultiFernet

from . import config

MIN_PASSWORD = 12
_hasher = PasswordHasher()
_dummy_hash = _hasher.hash(secrets.token_hex(16))


class ConfigError(Exception):
    pass


def secret_key_problem() -> str | None:
    if not config.SECRET_KEY:
        return ("FLEETWRIGHT_SECRET_KEY is not set. Put a long random value in .env, "
                "for example the output of: openssl rand -hex 32")
    if len(config.SECRET_KEY) < 16:
        return "FLEETWRIGHT_SECRET_KEY is too short: use at least 16 random characters"
    return None


def derived(purpose: str, key: str | None = None) -> bytes:
    problem = secret_key_problem()
    if problem:
        raise ConfigError(problem)
    return hashlib.sha256(f"fleetwright:{purpose}:{key or config.SECRET_KEY}".encode()).digest()


def _fernet_for(key: str) -> Fernet:
    return Fernet(base64.urlsafe_b64encode(derived("secrets", key)))


def _fernet() -> MultiFernet:
    """Encrypts under the current key; decrypts under it or any previous one."""
    return MultiFernet([_fernet_for(config.SECRET_KEY)] + [_fernet_for(k) for k in config.SECRET_KEY_PREVIOUS])


def encrypt(value: str) -> str:
    return _fernet().encrypt(value.encode()).decode()


class UndecryptableSecret(Exception):
    pass


def decrypt(value: str) -> str:
    try:
        return _fernet().decrypt(value.encode()).decode()
    except InvalidToken:
        # InvalidToken carries no message; say what's actually wrong.
        raise UndecryptableSecret(
            "this stored secret can't be decrypted with FLEETWRIGHT_SECRET_KEY: the key has changed. "
            "Put the old key in FLEETWRIGHT_SECRET_KEY_PREVIOUS and restart") from None


def under_current_key(token: str) -> bool:
    try:
        _fernet_for(config.SECRET_KEY).decrypt(token.encode())
        return True
    except InvalidToken:
        return False


def reencrypt(token: str) -> str:
    """The same secret under the current key. Raises InvalidToken if no known key opens it."""
    return _fernet().rotate(token.encode()).decode()


# What rotate_secrets found at this process's start, for the admin banner.
KEY_STATUS: dict = {}


def key_problem() -> str | None:
    if KEY_STATUS.get("key_changed") or KEY_STATUS.get("unreadable"):
        n = KEY_STATUS.get("unreadable", 0)
        return (f"FLEETWRIGHT_SECRET_KEY has changed, and {n} stored secret{'s' if n != 1 else ''} "
                "(SSH keys, notification passwords) can't be read with it. Put the old key in "
                "FLEETWRIGHT_SECRET_KEY_PREVIOUS and restart: FleetWright re-encrypts them under the new one.")
    return None


# Every stored secret: (table, id column, encrypted column).
ENCRYPTED_COLUMNS = [("ssh_credentials", "id", "private_key_enc"), ("notify_channels", "id", "secret_enc")]
KEY_CHECK = "secret_key_check"          # settings row: a known value encrypted under the key in use


async def rotate_secrets() -> dict:
    """At startup: re-encrypt whatever isn't under the current key yet, and check that
    the stored secrets can be read at all. Returns counts for the log and the
    Settings page: {"reencrypted", "unreadable", "key_changed"}."""
    from . import db
    out = {"reencrypted": 0, "unreadable": 0, "key_changed": False}
    for table, idcol, col in ENCRYPTED_COLUMNS:
        for row in await db.fetch(f"SELECT {idcol} AS id, {col} AS v FROM {table} WHERE {col} IS NOT NULL"):
            if under_current_key(row["v"]):
                continue
            try:
                new = reencrypt(row["v"])
            except InvalidToken:
                out["unreadable"] += 1
                continue
            await db.execute(f"UPDATE {table} SET {col} = %s WHERE {idcol} = %s", new, row["id"])
            out["reencrypted"] += 1
    check = await db.fetchval("SELECT value FROM settings WHERE key = %s", KEY_CHECK)
    if check and not under_current_key(check):
        try:
            check = reencrypt(check)
        except InvalidToken:
            out["key_changed"] = True
            check = None
    if out["key_changed"] or out["unreadable"]:
        return out   # keep the old check value: it still says which key the data needs
    await db.execute("""INSERT INTO settings (key, value) VALUES (%s, %s)
                        ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value""",
                     KEY_CHECK, check or encrypt("fleetwright"))
    return out


def session_secret() -> str:
    return derived("session").hex()


def hash_password(password: str) -> str:
    return _hasher.hash(password)


def check_password(stored: str | None, password: str) -> bool:
    try:
        # Hash something either way, so a wrong email takes as long as a wrong password.
        return _hasher.verify(stored or _dummy_hash, password) and stored is not None
    except (VerificationError, InvalidHashError):
        return False


def password_problem(password: str, confirm: str | None = None) -> str | None:
    if len(password) < MIN_PASSWORD:
        return f"Use at least {MIN_PASSWORD} characters."
    if confirm is not None and password != confirm:
        return "The two passwords don't match."
    return None


def new_token(nbytes: int = 32) -> str:
    return secrets.token_urlsafe(nbytes)


def token_hash(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()
