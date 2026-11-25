"""Accès SQLite.

- Requêtes toujours paramétrées (pas de concaténation SQL).
- Contraintes et triggers en base = défense en profondeur :
  solde jamais négatif, mises et grand livre non modifiables.
"""
import sqlite3
import time
from contextlib import contextmanager

from flask import current_app, g

SCHEMA = """
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS users (
    id            INTEGER PRIMARY KEY,
    username      TEXT    NOT NULL UNIQUE COLLATE NOCASE,
    password_hash TEXT    NOT NULL,
    role          TEXT    NOT NULL DEFAULT 'user' CHECK (role IN ('user', 'admin')),
    balance_cents INTEGER NOT NULL DEFAULT 0 CHECK (balance_cents >= 0),
    created_at    INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS sessions (
    token_hash TEXT    PRIMARY KEY,
    user_id    INTEGER NOT NULL REFERENCES users(id),
    expires_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS bets (
    id               INTEGER PRIMARY KEY,
    bookie_id        INTEGER NOT NULL REFERENCES users(id),
    title            TEXT    NOT NULL,
    description      TEXT    NOT NULL DEFAULT '',
    min_stake_cents  INTEGER NOT NULL CHECK (min_stake_cents > 0),
    bookie_fee_bp    INTEGER NOT NULL CHECK (bookie_fee_bp >= 0),
    closes_at        INTEGER NOT NULL,
    status           TEXT    NOT NULL DEFAULT 'OPEN'
                     CHECK (status IN ('OPEN', 'PROPOSED', 'DISPUTED', 'SETTLED', 'CANCELLED')),
    proposed_outcome TEXT    CHECK (proposed_outcome IN ('YES', 'NO')),
    proposed_at      INTEGER,
    final_outcome    TEXT    CHECK (final_outcome IN ('YES', 'NO')),
    created_at       INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS invitations (
    bet_id  INTEGER NOT NULL REFERENCES bets(id),
    user_id INTEGER NOT NULL REFERENCES users(id),
    PRIMARY KEY (bet_id, user_id)
);

CREATE TABLE IF NOT EXISTS wagers (
    id           INTEGER PRIMARY KEY,
    bet_id       INTEGER NOT NULL REFERENCES bets(id),
    user_id      INTEGER NOT NULL REFERENCES users(id),
    outcome      TEXT    NOT NULL CHECK (outcome IN ('YES', 'NO')),
    amount_cents INTEGER NOT NULL CHECK (amount_cents > 0),
    created_at   INTEGER NOT NULL,
    receipt      TEXT    NOT NULL,
    UNIQUE (bet_id, user_id)
);

-- Une mise ne peut jamais être modifiée ni supprimée (abuse story « modifier mon pari »)
CREATE TRIGGER IF NOT EXISTS wagers_no_update BEFORE UPDATE ON wagers
BEGIN SELECT RAISE(ABORT, 'wagers are immutable'); END;
CREATE TRIGGER IF NOT EXISTS wagers_no_delete BEFORE DELETE ON wagers
BEGIN SELECT RAISE(ABORT, 'wagers are immutable'); END;

CREATE TABLE IF NOT EXISTS disputes (
    bet_id     INTEGER NOT NULL REFERENCES bets(id),
    user_id    INTEGER NOT NULL REFERENCES users(id),
    reason     TEXT    NOT NULL,
    created_at INTEGER NOT NULL,
    PRIMARY KEY (bet_id, user_id)
);

-- Grand livre chaîné par hash : toute modification casse la chaîne (non-répudiation)
CREATE TABLE IF NOT EXISTS ledger (
    id           INTEGER PRIMARY KEY,
    user_id      INTEGER REFERENCES users(id),   -- NULL = compte plateforme
    amount_cents INTEGER NOT NULL,
    kind         TEXT    NOT NULL,
    ref          TEXT    NOT NULL,
    created_at   INTEGER NOT NULL,
    prev_hash    TEXT    NOT NULL,
    hash         TEXT    NOT NULL UNIQUE
);
CREATE TRIGGER IF NOT EXISTS ledger_no_update BEFORE UPDATE ON ledger
BEGIN SELECT RAISE(ABORT, 'ledger is append-only'); END;
CREATE TRIGGER IF NOT EXISTS ledger_no_delete BEFORE DELETE ON ledger
BEGIN SELECT RAISE(ABORT, 'ledger is append-only'); END;

-- Idempotence des notifications du prestataire de paiement (anti-rejeu)
CREATE TABLE IF NOT EXISTS payment_events (
    event_id   TEXT    PRIMARY KEY,
    user_id    INTEGER NOT NULL REFERENCES users(id),
    amount_cents INTEGER NOT NULL,
    created_at INTEGER NOT NULL
);
"""


def connect(path: str) -> sqlite3.Connection:
    # isolation_level=None : on gère les transactions explicitement (BEGIN IMMEDIATE)
    conn = sqlite3.connect(path, timeout=30, isolation_level=None, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA busy_timeout = 30000")
    return conn


def get_db() -> sqlite3.Connection:
    if "db" not in g:
        g.db = connect(current_app.config["DATABASE"])
        if current_app.config.get("IAST_TRACE"):
            from .iast import attach_sql_tracer
            attach_sql_tracer(g.db)
    return g.db


def close_db(_exc=None):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db(path: str):
    conn = connect(path)
    try:
        conn.execute("PRAGMA journal_mode = WAL")
        conn.executescript(SCHEMA)
    finally:
        conn.close()


@contextmanager
def transaction(db: sqlite3.Connection):
    """Transaction exclusive en écriture : sérialise les opérations sur les soldes."""
    db.execute("BEGIN IMMEDIATE")
    try:
        yield db
    except BaseException:
        db.execute("ROLLBACK")
        raise
    else:
        db.execute("COMMIT")


def now() -> int:
    """Horloge injectable (CLOCK) pour tester la clôture des paris sans attendre."""
    try:
        clock = current_app.config.get("CLOCK")
    except RuntimeError:  # hors contexte Flask
        clock = None
    return int(clock() if clock else time.time())
