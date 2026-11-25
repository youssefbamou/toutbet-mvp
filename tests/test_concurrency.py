"""Atelier 2 — « Le même utilisateur effectue de nombreux paris simultanément.
Y a-t-il un risque qu'il dépense plus que son solde ? »

1. On démontre le risque sur une implémentation NAÏVE (lecture du solde, vérification,
   puis écriture séparée) : plusieurs threads lisent le même solde avant qu'aucun n'écrive.
2. On vérifie que l'API réelle, servie par un vrai serveur HTTP multithread, résiste :
   le débit est conditionnel et atomique (UPDATE ... WHERE balance_cents >= ?) dans une
   transaction BEGIN IMMEDIATE, et la base refuse tout solde négatif (CHECK).
"""
import sqlite3
import threading
import time
from concurrent.futures import ThreadPoolExecutor

import pytest
import requests

from toutbet import create_app
from toutbet.devserver import make_dev_server
from toutbet.db import connect
from toutbet.payment_provider_mock import signed_deposit
from toutbet.security import limiter

PASSWORD = "MotDePasse-Test-123"


# ------------------------------------------------------------------ 1. Démonstration du risque

def naive_place_wager(db_path, user_id, amount, barrier):
    """Anti-modèle volontaire : check-then-act sans verrou (NE PAS UTILISER)."""
    conn = sqlite3.connect(db_path, timeout=30, isolation_level=None)
    balance = conn.execute("SELECT balance FROM u WHERE id = ?", (user_id,)).fetchone()[0]
    barrier.wait()  # tous les threads ont lu le même solde
    if balance >= amount:
        conn.execute("UPDATE u SET balance = ? WHERE id = ?", (balance - amount, user_id))
        conn.close()
        return True
    conn.close()
    return False


def test_naive_implementation_lets_user_overspend(tmp_path):
    db_path = str(tmp_path / "naive.sqlite3")
    conn = sqlite3.connect(db_path, isolation_level=None)
    conn.execute("CREATE TABLE u (id INTEGER PRIMARY KEY, balance INTEGER)")
    conn.execute("INSERT INTO u VALUES (1, 1000)")  # 10 €
    conn.close()

    n = 10
    barrier = threading.Barrier(n)
    with ThreadPoolExecutor(n) as pool:
        accepted = sum(pool.map(lambda _: naive_place_wager(db_path, 1, 1000, barrier), range(n)))
    # 10 paris de 10 € acceptés avec seulement 10 € : 90 € dépensés « en trop »
    assert accepted > 1


# ------------------------------------------------------------------ 2. API réelle sous concurrence

@pytest.fixture
def live_server(tmp_path):
    limiter.reset()
    app = create_app({
        "ENV": "testing",
        "DATABASE": str(tmp_path / "live.sqlite3"),
        "RATE_LIMIT_PER_MINUTE": 1_000_000,
    })
    server = make_dev_server(app, "127.0.0.1", 0)
    th = threading.Thread(target=server.serve_forever, daemon=True)
    th.start()
    yield app, f"http://127.0.0.1:{server.server_port}"
    server.shutdown()
    limiter.reset()


def _user(base, app, name, deposit=0):
    requests.post(f"{base}/auth/register", json={"username": name, "password": PASSWORD}, timeout=10).raise_for_status()
    token = requests.post(f"{base}/auth/login", json={"username": name, "password": PASSWORD}, timeout=10).json()["token"]
    if deposit:
        body, h = signed_deposit(app.config["PAYMENT_WEBHOOK_SECRET"], name, deposit)
        requests.post(f"{base}/payments/webhook", data=body, headers=h, timeout=10).raise_for_status()
    return {"Authorization": f"Bearer {token}"}


def test_many_simultaneous_wagers_never_overspend(live_server):
    app, base = live_server
    bookie_h = _user(base, app, "bookie")
    player_h = _user(base, app, "joueur", deposit=10_000)  # 100 €

    # 50 paris différents, le joueur invité partout, 50 mises de 10 € lancées en même temps
    closes = int(time.time()) + 3600
    bets = [requests.post(f"{base}/bets", headers=bookie_h, json={
        "title": f"Événement {i}", "closes_at": closes, "invitees": ["joueur"], "min_stake_cents": 100,
    }, timeout=10).json()["id"] for i in range(50)]

    def wager(bet_id):
        return requests.post(f"{base}/bets/{bet_id}/wagers", headers=player_h,
                             json={"outcome": "YES", "amount_cents": 1000}, timeout=10).status_code

    with ThreadPoolExecutor(50) as pool:
        codes = list(pool.map(wager, bets))

    assert codes.count(201) == 10                    # exactement 100 € / 10 €
    assert codes.count(409) == 40                    # insufficient_funds
    bal = requests.get(f"{base}/wallet", headers=player_h, timeout=10).json()["balance_cents"]
    assert bal == 0

    conn = connect(app.config["DATABASE"])
    escrow = conn.execute("SELECT SUM(amount_cents) FROM wagers").fetchone()[0]
    conn.close()
    assert escrow == 10_000                          # conservation : solde + séquestre = dépôt


def test_same_bet_hammered_concurrently(live_server):
    app, base = live_server
    bookie_h = _user(base, app, "bookie2")
    player_h = _user(base, app, "joueur2", deposit=10_000)
    bet = requests.post(f"{base}/bets", headers=bookie_h, json={
        "title": "Finale", "closes_at": int(time.time()) + 3600, "invitees": ["joueur2"]}, timeout=10).json()["id"]

    with ThreadPoolExecutor(30) as pool:
        codes = list(pool.map(lambda _: requests.post(
            f"{base}/bets/{bet}/wagers", headers=player_h,
            json={"outcome": "YES", "amount_cents": 500}, timeout=10).status_code, range(30)))

    assert codes.count(201) == 1                     # une seule mise par parieur et par pari
    assert requests.get(f"{base}/wallet", headers=player_h, timeout=10).json()["balance_cents"] == 9_500


def test_concurrent_withdrawals_never_overspend(live_server):
    app, base = live_server
    h = _user(base, app, "retrait", deposit=5_000)
    with ThreadPoolExecutor(20) as pool:
        codes = list(pool.map(lambda _: requests.post(
            f"{base}/wallet/withdraw", headers=h, json={"amount_cents": 1000}, timeout=10).status_code, range(20)))
    assert codes.count(200) == 5
    assert requests.get(f"{base}/wallet", headers=h, timeout=10).json()["balance_cents"] == 0
