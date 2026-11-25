"""Tests unitaires « security-first » de la redistribution : cas usuels, extrêmes, erreurs."""
import random

import pytest

from toutbet.settlement import compute_payouts


def test_usual_case():
    p = compute_payouts([(1, "YES", 1000), (2, "NO", 1000), (3, "YES", 3000)], "YES", 500, 200)
    assert p.platform_fee >= 250 and p.bookie_fee == 100
    assert p.winners[3] == 3 * p.winners[1] or abs(p.winners[3] - 3 * p.winners[1]) <= 3
    assert sum(p.winners.values()) + p.bookie_fee + p.platform_fee == 5000


def test_no_winner_full_refund_without_fees():
    p = compute_payouts([(1, "NO", 1000), (2, "NO", 500)], "YES", 500, 1000)
    assert p.refund and p.winners == {1: 1000, 2: 500} and p.bookie_fee == p.platform_fee == 0


def test_empty_pot():
    p = compute_payouts([], "YES", 500, 1000)
    assert p.winners == {} and p.platform_fee == 0


def test_one_cent_pot():
    p = compute_payouts([(1, "YES", 1)], "YES", 500, 1000)
    assert sum(p.winners.values()) + p.bookie_fee + p.platform_fee == 1


@pytest.mark.parametrize("seed", range(200))
def test_conservation_random(seed):
    """Propriété : aucun centime créé ni perdu, aucun gain négatif."""
    rnd = random.Random(seed)
    wagers = [(i, rnd.choice("YN") == "Y" and "YES" or "NO", rnd.randint(1, 100_000)) for i in range(rnd.randint(1, 40))]
    p = compute_payouts(wagers, rnd.choice(["YES", "NO"]), rnd.randint(0, 1000), rnd.randint(0, 1000))
    assert sum(p.winners.values()) + p.bookie_fee + p.platform_fee == sum(a for *_, a in wagers)
    assert all(v >= 0 for v in p.winners.values())


def test_end_to_end_money_conservation(api, client, clock, app):
    """Scénario complet : dépôts -> paris -> résultat -> redistribution -> retrait.
    À la fin, soldes + commissions plateforme + retraits == dépôts."""
    from toutbet.db import connect
    from toutbet.ledger import verify_chain

    bookie = api.user()
    players = [api.user(deposit_cents=10_000) for _ in range(5)]
    bet = api.bet(bookie, players, closes_in=120, bookie_fee_bp=300)
    for i, p in enumerate(players):
        assert api.wager(p, bet, "YES" if i % 2 else "NO", 1000 * (i + 1)).status_code == 201
    clock.advance(121)
    client.post(f"/bets/{bet}/result", json={"outcome": "YES"}, headers=bookie["h"])
    clock.advance(601)
    assert client.post(f"/bets/{bet}/settle", json={}, headers=bookie["h"]).status_code == 200
    client.post("/wallet/withdraw", json={"amount_cents": 2000}, headers=players[1]["h"])

    conn = connect(app.config["DATABASE"])
    balances = conn.execute("SELECT SUM(balance_cents) FROM users").fetchone()[0]
    platform = conn.execute("SELECT COALESCE(SUM(amount_cents),0) FROM ledger WHERE user_id IS NULL").fetchone()[0]
    withdrawn = -conn.execute("SELECT COALESCE(SUM(amount_cents),0) FROM ledger WHERE kind='WITHDRAW'").fetchone()[0]
    assert balances + platform + withdrawn == 50_000
    assert verify_chain(conn, app.config["SECRET_KEY"])
    conn.close()
