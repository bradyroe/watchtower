"""One local admin login. PBKDF2-SHA256 password hash, random session tokens stored hashed,
a CSRF token per session, and a lockout after repeated failures from one address."""
from __future__ import annotations

import hashlib
import hmac
import secrets
import time

import config

ITER = 600_000
LOCK_FAILS, LOCK_WINDOW = 5, 15 * 60


def hash_pw(pw: str, salt: bytes | None = None) -> str:
    salt = salt or secrets.token_bytes(16)
    dk = hashlib.pbkdf2_hmac("sha256", pw.encode(), salt, ITER)
    return f"pbkdf2_sha256${ITER}${salt.hex()}${dk.hex()}"


def check_pw(pw: str, stored: str) -> bool:
    try:
        _, it, salt, dk = stored.split("$")
        got = hashlib.pbkdf2_hmac("sha256", pw.encode(), bytes.fromhex(salt), int(it))
        return hmac.compare_digest(got.hex(), dk)
    except (ValueError, TypeError):
        return False


def set_password(store, user: str, pw: str) -> None:
    with store.db() as c:
        c.execute("INSERT INTO users(name,pw_hash,created) VALUES(?,?,?) ON CONFLICT(name) DO UPDATE SET pw_hash=excluded.pw_hash",
                  (user, hash_pw(pw), time.time()))
        c.execute("DELETE FROM sessions WHERE user=?", (user,))


def has_user(store) -> bool:
    with store.db() as c:
        return c.execute("SELECT COUNT(*) FROM users").fetchone()[0] > 0


def locked(store, ip: str) -> bool:
    with store.db() as c:
        c.execute("DELETE FROM login_fail WHERE ts<?", (time.time() - LOCK_WINDOW,))
        return c.execute("SELECT COUNT(*) FROM login_fail WHERE ip=?", (ip,)).fetchone()[0] >= LOCK_FAILS


def login(store, user: str, pw: str, ip: str) -> tuple[str, str] | None:
    """(session token, csrf) or None. The token is returned once and stored only as a hash."""
    if locked(store, ip):
        return None
    with store.db() as c:
        r = c.execute("SELECT pw_hash FROM users WHERE name=?", (user,)).fetchone()
    if not r or not check_pw(pw, r["pw_hash"]):
        if not r:
            check_pw(pw, hash_pw("x"))             # same work either way
        with store.db() as c:
            c.execute("INSERT INTO login_fail(ip,ts) VALUES(?,?)", (ip, time.time()))
        return None
    tok, csrf = secrets.token_urlsafe(32), secrets.token_urlsafe(24)
    with store.db() as c:
        c.execute("DELETE FROM sessions WHERE expires<?", (time.time(),))
        c.execute("INSERT INTO sessions(token_hash,user,csrf,expires,created) VALUES(?,?,?,?,?)",
                  (_h(tok), user, csrf, time.time() + config.SESSION_HOURS * 3600, time.time()))
        c.execute("DELETE FROM login_fail WHERE ip=?", (ip,))
    return tok, csrf


def session(store, tok: str | None) -> dict | None:
    if not tok:
        return None
    with store.db() as c:
        r = c.execute("SELECT user,csrf,expires FROM sessions WHERE token_hash=?", (_h(tok),)).fetchone()
    if not r or r["expires"] < time.time():
        return None
    return {"user": r["user"], "csrf": r["csrf"]}


def logout(store, tok: str | None) -> None:
    if tok:
        with store.db() as c:
            c.execute("DELETE FROM sessions WHERE token_hash=?", (_h(tok),))


def _h(tok: str) -> str:
    return hashlib.sha256(tok.encode()).hexdigest()
