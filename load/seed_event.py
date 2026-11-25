"""Prépare les données du test de charge : un bookie, un pari, N parieurs invités et crédités.

Usage : python load/seed_event.py --users 500 [--host http://127.0.0.1:5000]
Le secret du webhook est lu dans TOUTBET_PAYMENT_WEBHOOK_SECRET (le même que celui du serveur).
"""
import argparse
import json
import os
import sys
import time
from pathlib import Path

import requests

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from toutbet.payment_provider_mock import signed_deposit  # noqa: E402

PASSWORD = "MotDePasse-Charge-123"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--users", type=int, default=500)
    ap.add_argument("--host", default="http://127.0.0.1:5000")
    a = ap.parse_args()
    secret = os.environ.get("TOUTBET_PAYMENT_WEBHOOK_SECRET")
    if not secret:
        sys.exit("Définir TOUTBET_PAYMENT_WEBHOOK_SECRET (même valeur que pour le serveur).")
    run = str(int(time.time()))[-6:]
    names = [f"p{run}_{i}" for i in range(a.users)]
    s = requests.Session()
    for n in names:
        s.post(f"{a.host}/auth/register", json={"username": n, "password": PASSWORD})
        body, h = signed_deposit(secret, n, 10_000)
        s.post(f"{a.host}/payments/webhook", data=body, headers=h).raise_for_status()
    bookie = f"bookie{run}"
    s.post(f"{a.host}/auth/register", json={"username": bookie, "password": PASSWORD})
    tok = s.post(f"{a.host}/auth/login", json={"username": bookie, "password": PASSWORD}).json()["token"]
    bet = s.post(f"{a.host}/bets", headers={"Authorization": f"Bearer {tok}"}, json={
        "title": "Finale : l'équipe A gagne-t-elle ?", "closes_at": int(time.time()) + 6 * 3600,
        "min_stake_cents": 100}).json()["id"]
    for i in range(0, len(names), 100):  # invitations par lots de 100 (limite de l'API)
        s.post(f"{a.host}/bets/{bet}/invite", headers={"Authorization": f"Bearer {tok}"},
               json={"usernames": names[i:i + 100]}).raise_for_status()
    Path(__file__).with_name("seed.json").write_text(json.dumps({"bet_id": bet, "users": names}))
    print(f"Pari {bet} créé avec {len(names)} parieurs invités -> load/seed.json")


if __name__ == "__main__":
    main()
