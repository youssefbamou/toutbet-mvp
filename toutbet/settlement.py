"""Calcul de la redistribution (fonction pure, testée unitairement).

Tous les montants sont des entiers en centimes : pas d'erreur d'arrondi flottant.
Invariant : somme(gains) + commission bookie + commission plateforme == cagnotte.
"""
from dataclasses import dataclass


@dataclass(frozen=True)
class Payout:
    winners: dict          # user_id -> centimes
    bookie_fee: int
    platform_fee: int      # inclut le reliquat d'arrondi
    refund: bool           # True si aucun gagnant : remboursement intégral, sans commission


def compute_payouts(wagers, outcome: str, platform_fee_bp: int, bookie_fee_bp: int) -> Payout:
    """wagers : itérable de (user_id, outcome, amount_cents)."""
    wagers = list(wagers)
    pot = sum(a for _, _, a in wagers)
    winning = [(u, a) for u, o, a in wagers if o == outcome]
    if pot == 0:
        return Payout({}, 0, 0, False)
    if not winning:
        refunds = {}
        for u, _, a in wagers:
            refunds[u] = refunds.get(u, 0) + a
        return Payout(refunds, 0, 0, True)

    platform_fee = pot * platform_fee_bp // 10_000
    bookie_fee = pot * bookie_fee_bp // 10_000
    distributable = pot - platform_fee - bookie_fee
    winning_total = sum(a for _, a in winning)
    shares = {}
    for u, a in winning:
        shares[u] = shares.get(u, 0) + distributable * a // winning_total
    remainder = distributable - sum(shares.values())
    platform_fee += remainder
    # Pas d'assert (désactivé avec python -O) : contrôle explicite, fail-safe
    if sum(shares.values()) + bookie_fee + platform_fee != pot:
        raise RuntimeError("invariant de conservation violé")
    return Payout(shares, bookie_fee, platform_fee, False)
