"""Grand livre : SEUL endroit du code autorisé à modifier un solde.

Règle Semgrep personnalisée proposée : toute écriture sur `balance_cents`
en dehors de `register_transaction` est une alerte.
"""
import hashlib
import hmac
import sqlite3

from .db import now

GENESIS = "0" * 64


class InsufficientFunds(Exception):
    pass


def _entry_hash(secret: str, prev_hash: str, user_id, amount: int, kind: str, ref: str, ts: int) -> str:
    msg = f"{prev_hash}|{user_id}|{amount}|{kind}|{ref}|{ts}".encode()
    # HMAC : un attaquant qui accède à la base ne peut pas recalculer une chaîne valide sans la clé
    return hmac.new(secret.encode(), msg, hashlib.sha256).hexdigest()


def register_transaction(db: sqlite3.Connection, secret: str, user_id, amount_cents: int, kind: str, ref: str) -> None:
    """Crédite (amount > 0) ou débite (amount < 0) un utilisateur et écrit le grand livre.

    Doit être appelée DANS une transaction `BEGIN IMMEDIATE`.
    Le débit est conditionnel et atomique (`balance_cents >= ?`) : impossible
    de dépenser plus que son solde, même avec des requêtes simultanées.
    user_id=None : écriture sur le compte plateforme (pas de solde utilisateur).
    """
    if not isinstance(amount_cents, int) or amount_cents == 0:
        raise ValueError("montant invalide")
    if user_id is not None:
        if amount_cents < 0:
            cur = db.execute(
                "UPDATE users SET balance_cents = balance_cents + ? "
                "WHERE id = ? AND balance_cents >= ?",
                (amount_cents, user_id, -amount_cents),
            )
            if cur.rowcount != 1:
                raise InsufficientFunds()
        else:
            cur = db.execute(
                "UPDATE users SET balance_cents = balance_cents + ? WHERE id = ?",
                (amount_cents, user_id),
            )
            if cur.rowcount != 1:
                raise ValueError("utilisateur inconnu")

    row = db.execute("SELECT hash FROM ledger ORDER BY id DESC LIMIT 1").fetchone()
    prev_hash = row["hash"] if row else GENESIS
    ts = now()
    h = _entry_hash(secret, prev_hash, user_id, amount_cents, kind, ref, ts)
    db.execute(
        "INSERT INTO ledger (user_id, amount_cents, kind, ref, created_at, prev_hash, hash) "
        "VALUES (?, ?, ?, ?, ?, ?, ?)",
        (user_id, amount_cents, kind, ref, ts, prev_hash, h),
    )


def verify_chain(db: sqlite3.Connection, secret: str) -> bool:
    prev = GENESIS
    for r in db.execute("SELECT * FROM ledger ORDER BY id"):
        if r["prev_hash"] != prev:
            return False
        expected = _entry_hash(secret, r["prev_hash"], r["user_id"], r["amount_cents"], r["kind"], r["ref"], r["created_at"])
        if not hmac.compare_digest(expected, r["hash"]):
            return False
        prev = r["hash"]
    return True


def sign_receipt(secret: str, *parts) -> str:
    """Reçu signé (HMAC) remis au parieur : preuve opposable de sa mise."""
    msg = "|".join(str(p) for p in parts).encode()
    return hmac.new(secret.encode(), msg, hashlib.sha256).hexdigest()
