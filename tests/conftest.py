import itertools

import pytest

from toutbet import create_app
from toutbet.payment_provider_mock import signed_deposit
from toutbet.security import limiter

PASSWORD = "MotDePasse-Test-123"


class Clock:
    def __init__(self, t=1_800_000_000):
        self.t = t

    def __call__(self):
        return self.t

    def advance(self, seconds):
        self.t += seconds


@pytest.fixture
def clock():
    return Clock()


@pytest.fixture
def app(tmp_path, clock):
    limiter.reset()
    app = create_app({
        "ENV": "testing",
        "DATABASE": str(tmp_path / "test.sqlite3"),
        "CLOCK": clock,
        "RATE_LIMIT_PER_MINUTE": 100_000,
        "DISPUTE_WINDOW_SECONDS": 600,
    })
    yield app
    limiter.reset()


@pytest.fixture
def client(app):
    return app.test_client()


_counter = itertools.count()


class Api:
    """Petit client métier pour écrire les scénarios lisiblement."""

    def __init__(self, app, client):
        self.app, self.c = app, client

    def user(self, name=None, deposit_cents=0):
        name = name or f"user{next(_counter)}"
        r = self.c.post("/auth/register", json={"username": name, "password": PASSWORD})
        assert r.status_code == 201, r.json
        r = self.c.post("/auth/login", json={"username": name, "password": PASSWORD})
        token = r.json["token"]
        if deposit_cents:
            self.deposit(name, deposit_cents)
        return {"name": name, "token": token, "h": {"Authorization": f"Bearer {token}"}}

    def admin(self):
        from toutbet.db import connect
        u = self.user()
        conn = connect(self.app.config["DATABASE"])
        conn.execute("UPDATE users SET role = 'admin' WHERE username = ?", (u["name"],))
        conn.close()
        return u

    def deposit(self, name, amount, event_id=None):
        body, headers = signed_deposit(self.app.config["PAYMENT_WEBHOOK_SECRET"], name, amount, event_id)
        return self.c.post("/payments/webhook", data=body, headers=headers)

    def balance(self, u):
        return self.c.get("/wallet", headers=u["h"]).json["balance_cents"]

    def bet(self, bookie, invitees=(), closes_in=3600, **kw):
        payload = {"title": "Matis va-t-il réussir son créneau ?", "closes_at": self.app.config["CLOCK"]() + closes_in,
                   "invitees": [u["name"] for u in invitees], "min_stake_cents": 100}
        payload.update(kw)
        r = self.c.post("/bets", json=payload, headers=bookie["h"])
        assert r.status_code == 201, r.json
        return r.json["id"]

    def wager(self, u, bet_id, outcome="YES", amount=1000):
        return self.c.post(f"/bets/{bet_id}/wagers", json={"outcome": outcome, "amount_cents": amount}, headers=u["h"])


@pytest.fixture
def api(app, client):
    return Api(app, client)
