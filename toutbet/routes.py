"""API REST de ToutBet'."""
import hashlib
import hmac
import logging
import sqlite3

from flask import Blueprint, abort, current_app, g, jsonify, request
from pydantic import BaseModel, ValidationError

from . import schemas
from .db import get_db, now, transaction
from .ledger import InsufficientFunds, register_transaction, sign_receipt
from .security import client_ip, hash_password, issue_token, limiter, login_required, revoke_token, verify_password
from .settlement import compute_payouts

bp = Blueprint("api", __name__)
log = logging.getLogger("toutbet")
audit = logging.getLogger("toutbet.audit")


class ApiError(Exception):
    def __init__(self, status: int, code: str):
        self.status, self.code = status, code


def parse(model: type[BaseModel]):
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        raise ApiError(400, "invalid_json")
    try:
        return model.model_validate(data)
    except ValidationError as e:
        # On renvoie uniquement les noms de champs fautifs, jamais la valeur reçue ni le détail interne
        fields = sorted({".".join(str(p) for p in err["loc"]) for err in e.errors()})
        raise ApiError(422, "validation_error:" + ",".join(fields)[:200]) from None


def cfg(key):
    return current_app.config[key]


def _user_by_name(db, username):
    return db.execute("SELECT id, username FROM users WHERE username = ?", (username,)).fetchone()


def _bet_visible(db, bet_id: int):
    """Renvoie le pari si l'utilisateur courant y a droit, sinon 404 (pas de fuite d'existence)."""
    bet = db.execute("SELECT * FROM bets WHERE id = ?", (bet_id,)).fetchone()
    if bet is None:
        abort(404)
    if g.user["role"] == "admin" or bet["bookie_id"] == g.user["id"]:
        return bet
    inv = db.execute("SELECT 1 FROM invitations WHERE bet_id = ? AND user_id = ?", (bet_id, g.user["id"])).fetchone()
    if inv is None:
        abort(404)
    return bet


def _bet_json(db, bet):
    wagers = db.execute(
        "SELECT outcome, COUNT(*) n, SUM(amount_cents) total FROM wagers WHERE bet_id = ? GROUP BY outcome",
        (bet["id"],),
    ).fetchall()
    mine = db.execute(
        "SELECT outcome, amount_cents, receipt FROM wagers WHERE bet_id = ? AND user_id = ?",
        (bet["id"], g.user["id"]),
    ).fetchone()
    return {
        "id": bet["id"],
        "title": bet["title"],
        "description": bet["description"],
        "bookie_id": bet["bookie_id"],
        "min_stake_cents": bet["min_stake_cents"],
        "bookie_fee_bp": bet["bookie_fee_bp"],
        "platform_fee_bp": cfg("PLATFORM_FEE_BP"),
        "closes_at": bet["closes_at"],
        "status": bet["status"],
        "proposed_outcome": bet["proposed_outcome"],
        "final_outcome": bet["final_outcome"],
        "pool": {w["outcome"]: {"count": w["n"], "total_cents": w["total"]} for w in wagers},
        "my_wager": dict(mine) if mine else None,
    }


# ---------------------------------------------------------------- Auth

@bp.post("/auth/register")
def register():
    data = parse(schemas.RegisterIn)
    db = get_db()
    try:
        db.execute(
            "INSERT INTO users (username, password_hash, created_at) VALUES (?, ?, ?)",
            (data.username, hash_password(data.password), now()),
        )
    except sqlite3.IntegrityError:
        raise ApiError(409, "username_taken") from None
    audit.info("register username=%s ip=%s", data.username, client_ip())
    return jsonify({"status": "created"}), 201


@bp.post("/auth/login")
def login():
    data = parse(schemas.LoginIn)
    key = f"login-fail:{data.username.lower()}"
    if limiter.count(key) >= cfg("LOGIN_MAX_FAILURES"):
        audit.warning("login_locked username=%s ip=%s", data.username, client_ip())
        raise ApiError(429, "too_many_attempts")
    db = get_db()
    row = db.execute("SELECT id, password_hash FROM users WHERE username = ?", (data.username,)).fetchone()
    if not verify_password(row["password_hash"] if row else None, data.password):
        limiter.hit(key, limit=10_000)
        audit.warning("login_failed username=%s ip=%s", data.username, client_ip())
        raise ApiError(401, "invalid_credentials")  # même message que le compte existe ou non
    token = issue_token(row["id"])
    audit.info("login_ok user_id=%s ip=%s", row["id"], client_ip())
    return jsonify({"token": token, "expires_in": cfg("TOKEN_TTL_SECONDS")})


@bp.post("/auth/logout")
@login_required()
def logout():
    revoke_token(g.token)
    return jsonify({"status": "logged_out"})


# ---------------------------------------------------------------- Portefeuille

@bp.get("/wallet")
@login_required()
def wallet():
    db = get_db()
    bal = db.execute("SELECT balance_cents FROM users WHERE id = ?", (g.user["id"],)).fetchone()
    hist = db.execute(
        "SELECT amount_cents, kind, ref, created_at FROM ledger WHERE user_id = ? ORDER BY id DESC LIMIT 50",
        (g.user["id"],),
    ).fetchall()
    return jsonify({"balance_cents": bal["balance_cents"], "history": [dict(h) for h in hist]})


@bp.post("/wallet/withdraw")
@login_required()
def withdraw():
    data = parse(schemas.AmountIn)
    db = get_db()
    try:
        with transaction(db):
            register_transaction(db, cfg("SECRET_KEY"), g.user["id"], -data.amount_cents, "WITHDRAW", "payout-provider")
    except InsufficientFunds:
        raise ApiError(409, "insufficient_funds") from None
    audit.info("withdraw user_id=%s amount=%s", g.user["id"], data.amount_cents)
    # En production : appel au prestataire de paiement (virement) ici, après le débit
    return jsonify({"status": "withdrawn", "amount_cents": data.amount_cents})


@bp.post("/payments/webhook")
def payment_webhook():
    """Notification du prestataire de paiement (dépôt confirmé).

    Frontière de confiance : on vérifie la signature HMAC du corps brut,
    puis l'idempotence (event_id) pour empêcher le rejeu.
    """
    raw = request.get_data(cache=True)
    sig = request.headers.get("X-Signature", "")
    expected = hmac.new(cfg("PAYMENT_WEBHOOK_SECRET").encode(), raw, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(sig, expected):
        audit.warning("webhook_bad_signature ip=%s", client_ip())
        raise ApiError(401, "bad_signature")
    data = parse(schemas.WebhookIn)
    if data.amount_cents > cfg("MAX_DEPOSIT_CENTS"):
        raise ApiError(422, "amount_too_large")
    db = get_db()
    user = _user_by_name(db, data.username)
    if user is None:
        raise ApiError(422, "unknown_user")
    try:
        with transaction(db):
            db.execute(
                "INSERT INTO payment_events (event_id, user_id, amount_cents, created_at) VALUES (?, ?, ?, ?)",
                (data.event_id, user["id"], data.amount_cents, now()),
            )
            register_transaction(db, cfg("SECRET_KEY"), user["id"], data.amount_cents, "DEPOSIT", f"evt:{data.event_id}")
    except sqlite3.IntegrityError:
        return jsonify({"status": "already_processed"}), 200
    audit.info("deposit user_id=%s amount=%s event=%s", user["id"], data.amount_cents, data.event_id)
    return jsonify({"status": "credited"})


# ---------------------------------------------------------------- Paris

@bp.post("/bets")
@login_required()
def create_bet():
    data = parse(schemas.BetIn)
    t = now()
    if not (t + 60 <= data.closes_at <= t + 30 * 24 * 3600):
        raise ApiError(422, "validation_error:closes_at")
    if data.bookie_fee_bp > cfg("MAX_BOOKIE_FEE_BP"):
        raise ApiError(422, "validation_error:bookie_fee_bp")
    if data.min_stake_cents > cfg("MAX_STAKE_CENTS"):
        raise ApiError(422, "validation_error:min_stake_cents")
    db = get_db()
    with transaction(db):
        cur = db.execute(
            "INSERT INTO bets (bookie_id, title, description, min_stake_cents, bookie_fee_bp, closes_at, created_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            (g.user["id"], data.title, data.description, data.min_stake_cents, data.bookie_fee_bp, data.closes_at, t),
        )
        bet_id = cur.lastrowid
        _invite(db, bet_id, data.invitees)
    audit.info("bet_created bet_id=%s bookie_id=%s", bet_id, g.user["id"])
    return jsonify({"id": bet_id}), 201


def _invite(db, bet_id, usernames):
    for name in usernames:
        u = _user_by_name(db, name)
        if u is None:
            raise ApiError(422, "unknown_invitee")
        if u["id"] == g.user["id"]:
            raise ApiError(422, "bookie_cannot_bet")
        db.execute("INSERT OR IGNORE INTO invitations (bet_id, user_id) VALUES (?, ?)", (bet_id, u["id"]))


@bp.get("/bets")
@login_required()
def list_bets():
    db = get_db()
    rows = db.execute(
        "SELECT DISTINCT b.* FROM bets b LEFT JOIN invitations i ON i.bet_id = b.id "
        "WHERE b.bookie_id = ? OR i.user_id = ? ORDER BY b.id DESC LIMIT 100",
        (g.user["id"], g.user["id"]),
    ).fetchall()
    return jsonify([_bet_json(db, b) for b in rows])


@bp.get("/bets/<int(max=9223372036854775807):bet_id>")
@login_required()
def get_bet(bet_id):
    db = get_db()
    return jsonify(_bet_json(db, _bet_visible(db, bet_id)))


@bp.post("/bets/<int(max=9223372036854775807):bet_id>/invite")
@login_required()
def invite(bet_id):
    data = parse(schemas.InviteIn)
    db = get_db()
    bet = _bet_visible(db, bet_id)
    if bet["bookie_id"] != g.user["id"]:
        abort(403)
    if bet["status"] != "OPEN" or now() >= bet["closes_at"]:
        raise ApiError(409, "bet_closed")
    with transaction(db):
        _invite(db, bet_id, data.usernames)
    return jsonify({"status": "invited"})


@bp.post("/bets/<int(max=9223372036854775807):bet_id>/wagers")
@login_required()
def place_wager(bet_id):
    data = parse(schemas.WagerIn)
    db = get_db()
    uid = g.user["id"]
    try:
        with transaction(db):
            # Toutes les vérifications sont refaites DANS la transaction (pas de TOCTOU)
            bet = _bet_visible(db, bet_id)
            if bet["bookie_id"] == uid:
                raise ApiError(403, "bookie_cannot_bet")
            if bet["status"] != "OPEN" or now() >= bet["closes_at"]:
                raise ApiError(409, "bet_closed")
            if data.amount_cents < bet["min_stake_cents"]:
                raise ApiError(422, "below_min_stake")
            if data.amount_cents > cfg("MAX_STAKE_CENTS"):
                raise ApiError(422, "above_max_stake")
            register_transaction(db, cfg("SECRET_KEY"), uid, -data.amount_cents, "WAGER", f"bet:{bet_id}")
            t = now()
            receipt = sign_receipt(cfg("SECRET_KEY"), "wager", bet_id, uid, data.outcome, data.amount_cents, t)
            db.execute(
                "INSERT INTO wagers (bet_id, user_id, outcome, amount_cents, created_at, receipt) VALUES (?, ?, ?, ?, ?, ?)",
                (bet_id, uid, data.outcome, data.amount_cents, t, receipt),
            )
    except InsufficientFunds:
        raise ApiError(409, "insufficient_funds") from None
    except sqlite3.IntegrityError:
        raise ApiError(409, "already_wagered") from None
    audit.info("wager bet_id=%s user_id=%s outcome=%s amount=%s", bet_id, uid, data.outcome, data.amount_cents)
    return jsonify({"status": "accepted", "receipt": receipt, "created_at": t}), 201


@bp.post("/bets/<int(max=9223372036854775807):bet_id>/result")
@login_required()
def propose_result(bet_id):
    data = parse(schemas.ResultIn)
    db = get_db()
    with transaction(db):
        bet = _bet_visible(db, bet_id)
        if bet["bookie_id"] != g.user["id"]:
            abort(403)
        if now() < bet["closes_at"]:
            raise ApiError(409, "bet_not_closed")
        cur = db.execute(
            "UPDATE bets SET status = 'PROPOSED', proposed_outcome = ?, proposed_at = ? WHERE id = ? AND status = 'OPEN'",
            (data.outcome, now(), bet_id),
        )
        if cur.rowcount != 1:
            raise ApiError(409, "invalid_state")
    audit.info("result_proposed bet_id=%s outcome=%s by=%s", bet_id, data.outcome, g.user["id"])
    return jsonify({"status": "PROPOSED", "dispute_window_seconds": cfg("DISPUTE_WINDOW_SECONDS")})


@bp.post("/bets/<int(max=9223372036854775807):bet_id>/dispute")
@login_required()
def dispute(bet_id):
    data = parse(schemas.DisputeIn)
    db = get_db()
    with transaction(db):
        bet = _bet_visible(db, bet_id)
        has_wager = db.execute("SELECT 1 FROM wagers WHERE bet_id = ? AND user_id = ?", (bet_id, g.user["id"])).fetchone()
        if not has_wager:
            abort(403)
        if bet["status"] not in ("PROPOSED", "DISPUTED") or now() >= bet["proposed_at"] + cfg("DISPUTE_WINDOW_SECONDS"):
            raise ApiError(409, "dispute_window_closed")
        try:
            db.execute(
                "INSERT INTO disputes (bet_id, user_id, reason, created_at) VALUES (?, ?, ?, ?)",
                (bet_id, g.user["id"], data.reason, now()),
            )
        except sqlite3.IntegrityError:
            raise ApiError(409, "already_disputed") from None
        db.execute("UPDATE bets SET status = 'DISPUTED' WHERE id = ?", (bet_id,))
    audit.info("dispute bet_id=%s user_id=%s", bet_id, g.user["id"])
    return jsonify({"status": "DISPUTED"})


@bp.post("/bets/<int(max=9223372036854775807):bet_id>/settle")
@login_required()
def settle(bet_id):
    """Redistribution. Un pari non contesté est réglé après le délai de contestation ;
    un pari contesté ne peut être tranché que par un administrateur (arbitrage)."""
    data = parse(schemas.SettleIn)
    db = get_db()
    with transaction(db):
        bet = _bet_visible(db, bet_id)
        is_admin = g.user["role"] == "admin"
        if bet["status"] == "PROPOSED":
            if now() < bet["proposed_at"] + cfg("DISPUTE_WINDOW_SECONDS"):
                raise ApiError(409, "dispute_window_open")
            if data.outcome is not None and not is_admin:
                abort(403)
            outcome = data.outcome or bet["proposed_outcome"]
        elif bet["status"] == "DISPUTED":
            if not is_admin:
                abort(403)
            if data.outcome is None:
                raise ApiError(422, "validation_error:outcome")
            outcome = data.outcome
        else:
            raise ApiError(409, "invalid_state")

        # Transition atomique : une seule requête peut passer ici => pas de double paiement
        cur = db.execute(
            "UPDATE bets SET status = 'SETTLED', final_outcome = ? WHERE id = ? AND status = ?",
            (outcome, bet_id, bet["status"]),
        )
        if cur.rowcount != 1:
            raise ApiError(409, "invalid_state")
        wagers = db.execute("SELECT user_id, outcome, amount_cents FROM wagers WHERE bet_id = ?", (bet_id,)).fetchall()
        p = compute_payouts(
            [(w["user_id"], w["outcome"], w["amount_cents"]) for w in wagers],
            outcome, cfg("PLATFORM_FEE_BP"), bet["bookie_fee_bp"],
        )
        key = cfg("SECRET_KEY")
        ref = f"bet:{bet_id}"
        for uid, amount in p.winners.items():
            if amount > 0:
                register_transaction(db, key, uid, amount, "REFUND" if p.refund else "PAYOUT", ref)
        if p.bookie_fee:
            register_transaction(db, key, bet["bookie_id"], p.bookie_fee, "BOOKIE_FEE", ref)
        if p.platform_fee:
            register_transaction(db, key, None, p.platform_fee, "PLATFORM_FEE", ref)
    audit.info("settled bet_id=%s outcome=%s by=%s", bet_id, outcome, g.user["id"])
    return jsonify({"status": "SETTLED", "final_outcome": outcome, "refund": p.refund,
                    "payouts": {str(k): v for k, v in p.winners.items()},
                    "bookie_fee_cents": p.bookie_fee, "platform_fee_cents": p.platform_fee})


@bp.post("/bets/<int(max=9223372036854775807):bet_id>/cancel")
@login_required(role="admin")
def cancel(bet_id):
    """Annulation par un administrateur (fraude avérée) : remboursement intégral."""
    db = get_db()
    with transaction(db):
        cur = db.execute(
            "UPDATE bets SET status = 'CANCELLED' WHERE id = ? AND status IN ('OPEN', 'PROPOSED', 'DISPUTED')",
            (bet_id,),
        )
        if cur.rowcount != 1:
            raise ApiError(409, "invalid_state")
        for w in db.execute("SELECT user_id, amount_cents FROM wagers WHERE bet_id = ?", (bet_id,)).fetchall():
            register_transaction(db, cfg("SECRET_KEY"), w["user_id"], w["amount_cents"], "REFUND", f"bet:{bet_id}")
    audit.info("cancelled bet_id=%s by=%s", bet_id, g.user["id"])
    return jsonify({"status": "CANCELLED"})


@bp.get("/health")
def health():
    return jsonify({"status": "ok"})
