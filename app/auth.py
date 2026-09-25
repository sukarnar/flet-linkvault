"""Password hashing (scrypt, stdlib), login tokens and input validation."""
from __future__ import annotations

import hashlib
import hmac
import re
import secrets

import db
from config import SESSION_DAYS

USERNAME_RE = re.compile(r"^[A-Za-z0-9_]{3,24}$")
RESERVED = {"admin", "root", "support", "system", "anonymous", "linkvault", "moderator"}
_N, _R, _P = 2**14, 8, 1


def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    digest = hashlib.scrypt(password.encode(), salt=salt, n=_N, r=_R, p=_P, dklen=32)
    return f"scrypt${_N}${_R}${_P}${salt.hex()}${digest.hex()}"


def verify_password(password: str, stored: str) -> bool:
    try:
        _, n, r, p, salt, digest = stored.split("$")
        calc = hashlib.scrypt(password.encode(), salt=bytes.fromhex(salt),
                              n=int(n), r=int(r), p=int(p), dklen=len(digest) // 2)
        return hmac.compare_digest(calc.hex(), digest)
    except (ValueError, TypeError):
        return False


# Used to spend the same time when the username doesn't exist (no user enumeration by timing)
_DUMMY_HASH = hash_password(secrets.token_hex(8))


def validate_username(username: str) -> str | None:
    if not USERNAME_RE.match(username or ""):
        return "3-24 characters: letters, numbers and underscore only."
    if username.lower() in RESERVED:
        return "That username is reserved."
    return None


def validate_password(password: str, username: str) -> str | None:
    if len(password or "") < 10:
        return "Use at least 10 characters."
    if len(password) > 200:
        return "That password is too long."
    if username and username.lower() in password.lower():
        return "Your password shouldn't contain your username."
    if len(set(password)) < 5:
        return "That password is too simple."
    return None


def _token_hash(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def register(username: str, password: str) -> dict:
    uid = db.create_user(username, hash_password(password))
    return db.get_user(uid)


def authenticate(username: str, password: str) -> dict | None:
    user = db.get_user_by_name(username)
    if user is None:
        verify_password(password, _DUMMY_HASH)
        return None
    return user if verify_password(password, user["password_hash"]) else None


def start_session(user_id: int) -> str:
    """Returns a random token for the browser; only its SHA-256 is stored."""
    token = secrets.token_urlsafe(32)
    db.create_session(user_id, _token_hash(token), SESSION_DAYS * 86400)
    return token


def resume_session(token: str | None) -> dict | None:
    if not token or not isinstance(token, str) or len(token) > 100:
        return None
    return db.session_user(_token_hash(token))


def end_session(token: str | None) -> None:
    if token:
        db.delete_session(_token_hash(token))
