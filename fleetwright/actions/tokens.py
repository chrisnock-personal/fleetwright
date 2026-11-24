"""API tokens: per person, shown once, stored as hashes, with an optional expiry and an
optional lower role than the person's."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Optional

from .. import db, security
from .core import RANK, ROLES, ActionError, Principal, action, invalid, not_found

PREFIX = "fwt_"


@action("tokens.list", "viewer")
async def list_tokens(who: Principal, everyone: bool = False) -> dict:
    """Your API tokens (an admin can ask for everyone's): name, role, expiry and when each was last used."""
    if everyone and not who.can("admin"):
        raise ActionError("forbidden", "Seeing everyone's tokens needs the Admin role.")
    rows = await db.fetch("""SELECT t.id, t.name, t.prefix, t.role, t.expires_at, t.last_used_at, t.revoked_at,
                                    t.created_at, u.name AS owner, u.id AS user_id
                               FROM api_tokens t JOIN users u ON u.id = t.user_id
                              WHERE (%s OR t.user_id = %s) ORDER BY t.revoked_at NULLS FIRST, t.id DESC""",
                          everyone, who.user_id)
    return {"tokens": rows}


@action("tokens.create", "viewer")
async def create_token(who: Principal, name: str, role: Optional[str] = None,
                       expires_days: Optional[int] = None) -> dict:
    """Create an API token for yourself, with your role or a lower one. The token is returned only this once."""
    name = (name or "").strip()[:80]
    role = role or who.role
    if not name:
        raise invalid("Give the token a name, such as what will use it.")
    if role not in ROLES:
        raise invalid(f"role is one of {', '.join(ROLES)}")
    if RANK[role] > RANK[who.role]:
        raise ActionError("forbidden", f"A token can't have more than your own role ({ROLES[who.role]}).")
    if expires_days is not None and not 1 <= int(expires_days) <= 3650:
        raise invalid("expires_days is 1 to 3650, or leave it out for a token that doesn't expire.")
    token = PREFIX + security.new_token(30)
    expires = datetime.now(timezone.utc) + timedelta(days=int(expires_days)) if expires_days else None
    try:
        tid = await db.fetchval("""INSERT INTO api_tokens (user_id, name, token_hash, prefix, role, expires_at)
                                   VALUES (%s, %s, %s, %s, %s, %s) RETURNING id""",
                                who.user_id, name, security.token_hash(token), token[:10], role, expires)
    except Exception as e:
        if "unique" in str(e).lower():
            raise invalid(f"You already have a token called {name}.") from e
        raise
    await db.audit(who.actor, f"Created API token '{name}' ({ROLES[role]}"
                   + (f", expires {expires:%d %b %Y}" if expires else "") + ")")
    return {"token_id": tid, "name": name, "role": role, "expires_at": expires, "token": token}


@action("tokens.revoke", "viewer")
async def revoke_token(who: Principal, token_id: int) -> dict:
    """Revoke one of your API tokens (an admin can revoke anyone's)."""
    t = await db.fetchone("SELECT t.*, u.name AS owner FROM api_tokens t JOIN users u ON u.id = t.user_id "
                          "WHERE t.id = %s", token_id)
    if not t or (t["user_id"] != who.user_id and not who.can("admin")):
        raise not_found("token")
    await db.execute("UPDATE api_tokens SET revoked_at = NOW() WHERE id = %s AND revoked_at IS NULL", token_id)
    await db.audit(who.actor, f"Revoked API token '{t['name']}' of {t['owner']}")
    return {"revoked": t["name"]}


async def authenticate(token: str) -> Optional[Principal]:
    """The Principal an API token acts as, or None. Its role is the lower of the token's and
    the person's now (a person demoted since keeps no more than their new role)."""
    if not token.startswith(PREFIX):
        return None
    row = await db.fetchone("""SELECT t.id, t.name, t.role AS token_role, t.last_used_at, u.id AS user_id,
                                      u.name AS user_name, u.role AS user_role
                                 FROM api_tokens t JOIN users u ON u.id = t.user_id
                                WHERE t.token_hash = %s AND t.revoked_at IS NULL
                                  AND (t.expires_at IS NULL OR t.expires_at > NOW())""",
                            security.token_hash(token))
    if not row:
        return None
    role = min(row["token_role"], row["user_role"], key=lambda r: RANK.get(r, -1))
    last = row["last_used_at"]
    if not last or datetime.now(timezone.utc) - last > timedelta(minutes=1):
        await db.execute("UPDATE api_tokens SET last_used_at = NOW() WHERE id = %s", row["id"])
    return Principal(row["user_id"], row["user_name"], role, row["id"], row["name"])
