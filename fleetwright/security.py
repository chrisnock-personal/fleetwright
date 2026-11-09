"""Encryption of stored secrets, password hashing and tokens."""

from __future__ import annotations

import base64
import hashlib
import secrets

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError
from cryptography.fernet import Fernet

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


def derived(purpose: str) -> bytes:
    problem = secret_key_problem()
    if problem:
        raise ConfigError(problem)
    return hashlib.sha256(f"fleetwright:{purpose}:{config.SECRET_KEY}".encode()).digest()


def _fernet() -> Fernet:
    return Fernet(base64.urlsafe_b64encode(derived("secrets")))


def encrypt(value: str) -> str:
    return _fernet().encrypt(value.encode()).decode()


def decrypt(value: str) -> str:
    return _fernet().decrypt(value.encode()).decode()


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
