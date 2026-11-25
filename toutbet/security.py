"""Authentification, limitation de débit et en-têtes de sécurité."""
import hashlib
import secrets
import threading
import time
from collections import defaultdict, deque
from functools import wraps

from flask import abort, current_app, g, request
from werkzeug.security import check_password_hash, generate_password_hash

from .db import get_db, now

# Hash factice : évite qu'un login sur un compte inexistant réponde plus vite (énumération)
_DUMMY_HASH = generate_password_hash(secrets.token_hex(16))


def hash_password(password: str) -> str:
    return generate_password_hash(password)  # scrypt par défaut (werkzeug >= 3)


def verify_password(stored_hash: str | None, password: str) -> bool:
    return check_password_hash(stored_hash or _DUMMY_HASH, password) and stored_hash is not None


def _token_digest(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def issue_token(user_id: int) -> str:
    token = secrets.token_urlsafe(32)
    db = get_db()
    db.execute(
        "INSERT INTO sessions (token_hash, user_id, expires_at) VALUES (?, ?, ?)",
        (_token_digest(token), user_id, now() + current_app.config["TOKEN_TTL_SECONDS"]),
    )
    return token  # seul le hash est stocké en base


def revoke_token(token: str) -> None:
    get_db().execute("DELETE FROM sessions WHERE token_hash = ?", (_token_digest(token),))


def _bearer() -> str | None:
    header = request.headers.get("Authorization", "")
    if not header.startswith("Bearer "):
        return None
    token = header[7:].strip()
    return token if 20 <= len(token) <= 128 else None


def login_required(role: str | None = None):
    def decorator(view):
        @wraps(view)
        def wrapped(*args, **kwargs):
            token = _bearer()
            if not token:
                abort(401)
            row = get_db().execute(
                "SELECT u.id, u.username, u.role FROM sessions s JOIN users u ON u.id = s.user_id "
                "WHERE s.token_hash = ? AND s.expires_at > ?",
                (_token_digest(token), now()),
            ).fetchone()
            if row is None:
                abort(401)
            if role and row["role"] != role:
                abort(403)
            g.user = row
            g.token = token
            return view(*args, **kwargs)
        return wrapped
    return decorator


class RateLimiter:
    """Fenêtre glissante en mémoire (MVP mono-instance ; Redis en production)."""

    def __init__(self):
        self._hits: dict[str, deque] = defaultdict(deque)
        self._lock = threading.Lock()

    def hit(self, key: str, limit: int, window: float = 60.0) -> bool:
        t = time.monotonic()
        with self._lock:
            q = self._hits[key]
            while q and q[0] <= t - window:
                q.popleft()
            if len(q) >= limit:
                return False
            q.append(t)
            return True

    def count(self, key: str, window: float = 60.0) -> int:
        t = time.monotonic()
        with self._lock:
            q = self._hits[key]
            while q and q[0] <= t - window:
                q.popleft()
            return len(q)

    def reset(self):
        with self._lock:
            self._hits.clear()


limiter = RateLimiter()


def client_ip() -> str:
    # Derrière un reverse proxy, configurer werkzeug ProxyFix plutôt que lire X-Forwarded-For à la main
    return request.remote_addr or "unknown"


SECURITY_HEADERS = {
    "Strict-Transport-Security": "max-age=63072000; includeSubDomains",
    "Content-Security-Policy": "default-src 'none'; frame-ancestors 'none'",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Cache-Control": "no-store",
    "Cross-Origin-Resource-Policy": "same-origin",
}
