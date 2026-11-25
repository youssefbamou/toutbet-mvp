"""Test de charge Locust : afflux de nombreux parieurs simultanés sur un même événement.

Scénario « finale de la Coupe » : un bookie ouvre un pari, des centaines de parieurs
invités se connectent en même temps, consultent le pari et misent.

Préparation (un seul terminal suffit) :
    export TOUTBET_RATE_LIMIT_PER_MINUTE=1000000   # sinon le rate-limit par IP bloque Locust (une seule IP)
    python -m toutbet                              # API sur http://127.0.0.1:5000
    python load/seed_event.py --users 500          # crée le pari + 500 parieurs crédités

Lancement avec interface Web (pour la copie d'écran) :
    locust -f load/locustfile.py --host http://127.0.0.1:5000
    puis ouvrir http://localhost:8089 (ex. 500 utilisateurs, montée de 50/s)

Deuxième scénario, sans désactiver le rate-limit : on vérifie que l'API répond 429
(protection DoS) au lieu de s'effondrer.
"""
import json
import random
from pathlib import Path

from locust import HttpUser, between, events, task

SEED_FILE = Path(__file__).with_name("seed.json")
PASSWORD = "MotDePasse-Charge-123"
_state = {"users": [], "bet_id": None, "next": 0}


@events.init.add_listener
def _load_seed(environment, **_):
    data = json.loads(SEED_FILE.read_text())
    _state["users"], _state["bet_id"] = data["users"], data["bet_id"]


class Parieur(HttpUser):
    wait_time = between(0.5, 2)

    def on_start(self):
        i = _state["next"] % len(_state["users"])
        _state["next"] += 1
        self.username = _state["users"][i]
        r = self.client.post("/auth/login", json={"username": self.username, "password": PASSWORD}, name="/auth/login")
        self.h = {"Authorization": f"Bearer {r.json()['token']}"} if r.ok else {}
        self.has_bet = False

    @task(5)
    def consulter_pari(self):
        self.client.get(f"/bets/{_state['bet_id']}", headers=self.h, name="/bets/[id]")

    @task(2)
    def consulter_portefeuille(self):
        self.client.get("/wallet", headers=self.h, name="/wallet")

    @task(3)
    def miser(self):
        with self.client.post(f"/bets/{_state['bet_id']}/wagers", headers=self.h, name="/bets/[id]/wagers",
                              json={"outcome": random.choice(["YES", "NO"]), "amount_cents": random.choice([100, 500, 1000])},
                              catch_response=True) as r:
            # 409 « already_wagered » est un comportement normal (une mise par parieur)
            if r.status_code in (201, 409):
                r.success()
