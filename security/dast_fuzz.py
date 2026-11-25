"""Exploration dynamique de l'API ToutBet' : DAST + IAST + Fuzzing.

Lance l'application sur un vrai serveur HTTP local, en mode IAST (trace SQL par requête),
puis :
  - DAST   : tests boîte noire (en-têtes, méthodes, CORS, authentification, IDOR, fuites)
  - Fuzzing: entrées aléatoires / malformées sur l'API de création de paris
  - IAST   : corrélation entre chaque requête HTTP et le SQL réellement exécuté

Usage : python security/dast_fuzz.py [--iterations 500] [--seed 42]
Sorties : security/reports/dast_report.md, security/reports/server.log
Pour un scan OWASP ZAP complémentaire, voir security/README.md.
"""
import argparse
import json
import logging
import os
import random
import re
import string
import sys
import tempfile
import threading
import time
from collections import Counter
from pathlib import Path

import requests

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from toutbet import create_app
from toutbet.devserver import make_dev_server  # noqa: E402
from toutbet.payment_provider_mock import signed_deposit  # noqa: E402

REPORTS = ROOT / "security" / "reports"
LEAK_PATTERNS = ["Traceback", "File \"", "sqlite", "SELECT ", "INSERT ", "werkzeug", "pydantic",
                 "/home/", "/srv/", "line ", "Exception", "Error:", "toutbet/"]
PASSWORD = "MotDePasse-Dast-123"
results = []


def record(kind, name, ok, detail=""):
    results.append({"type": kind, "test": name, "ok": ok, "detail": detail})


def leaks(text):
    return [p for p in LEAK_PATTERNS if p in text]


# ---------------------------------------------------------------- serveur instrumenté

def start_server(db_path, log_path):
    os.environ["TOUTBET_IAST_TRACE"] = "1"
    app = create_app({"ENV": "testing", "DATABASE": db_path, "RATE_LIMIT_PER_MINUTE": 1_000_000})
    handler = logging.FileHandler(log_path, mode="w", encoding="utf-8")
    handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(name)s %(message)s"))
    logging.getLogger().addHandler(handler)
    server = make_dev_server(app, "127.0.0.1", 0)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return app, server, f"http://127.0.0.1:{server.server_port}"


def make_user(base, app, name, deposit=0):
    requests.post(f"{base}/auth/register", json={"username": name, "password": PASSWORD}, timeout=10)
    tok = requests.post(f"{base}/auth/login", json={"username": name, "password": PASSWORD}, timeout=10).json()["token"]
    if deposit:
        body, h = signed_deposit(app.config["PAYMENT_WEBHOOK_SECRET"], name, deposit)
        requests.post(f"{base}/payments/webhook", data=body, headers=h, timeout=10)
    return {"Authorization": f"Bearer {tok}"}


# ---------------------------------------------------------------- DAST

def dast(base, app):
    r = requests.get(f"{base}/health", timeout=10)
    for h in ["Strict-Transport-Security", "Content-Security-Policy", "X-Content-Type-Options",
              "X-Frame-Options", "Referrer-Policy", "Cache-Control"]:
        record("DAST", f"En-tête {h} présent", h in r.headers, r.headers.get(h, "absent"))
    record("DAST", "En-tête Server ne révèle pas de version précise",
           not re.search(r"\d+\.\d+", r.headers.get("Server", "")), r.headers.get("Server", "absent"))

    r = requests.options(f"{base}/bets", headers={"Origin": "https://evil.example", "Access-Control-Request-Method": "POST"}, timeout=10)
    record("DAST", "CORS : origine tierce non autorisée",
           "Access-Control-Allow-Origin" not in r.headers, r.headers.get("Access-Control-Allow-Origin", "aucun ACAO"))
    r = requests.request("TRACE", f"{base}/bets", timeout=10)
    record("DAST", "Méthode TRACE refusée", r.status_code in (404, 405), str(r.status_code))

    for path, method in [("/wallet", "GET"), ("/bets", "GET"), ("/bets", "POST"), ("/wallet/withdraw", "POST"),
                         ("/bets/1/settle", "POST"), ("/bets/1/cancel", "POST")]:
        r = requests.request(method, f"{base}{path}", json={}, timeout=10)
        record("DAST", f"{method} {path} sans jeton -> 401", r.status_code == 401, str(r.status_code))

    for tok in ["", "null", "' OR 1=1 --", "A" * 43, "../../etc/passwd" + "x" * 30]:
        r = requests.get(f"{base}/wallet", headers={"Authorization": f"Bearer {tok}"}, timeout=10)
        record("DAST", f"Jeton forgé {tok[:20]!r} rejeté", r.status_code == 401, str(r.status_code))

    bookie = make_user(base, app, "dast_bookie")
    outsider = make_user(base, app, "dast_outsider", deposit=5000)
    bet = requests.post(f"{base}/bets", headers=bookie, json={"title": "Pari privé", "closes_at": int(time.time()) + 3600}, timeout=10).json()["id"]
    codes = Counter(requests.get(f"{base}/bets/{i}", headers=outsider, timeout=10).status_code for i in range(1, bet + 20))
    record("DAST", "IDOR : énumération des paris d'autrui impossible", set(codes) == {404}, dict(codes))
    r = requests.post(f"{base}/bets/{bet}/wagers", headers=outsider, json={"outcome": "YES", "amount_cents": 100}, timeout=10)
    record("DAST", "IDOR : mise sur pari non invité refusée", r.status_code == 404, str(r.status_code))
    r = requests.post(f"{base}/bets/{bet}/cancel", headers=bookie, timeout=10)
    record("DAST", "Élévation : annulation réservée à l'admin", r.status_code == 403, str(r.status_code))

    r = requests.post(f"{base}/payments/webhook", data=b'{"event_id":"evt_aaaaaaaa","type":"payment.succeeded","username":"dast_outsider","amount_cents":99999}',
                      headers={"Content-Type": "application/json", "X-Signature": "deadbeef"}, timeout=10)
    record("DAST", "Webhook paiement non signé refusé", r.status_code == 401, str(r.status_code))

    r = requests.get(f"{base}/this/does/not/exist", timeout=10)
    record("DAST", "404 générique sans fuite", r.status_code == 404 and not leaks(r.text), r.text[:120])
    r = requests.post(f"{base}/auth/login", data="{{{", headers={"Content-Type": "application/json"}, timeout=10)
    record("DAST", "JSON invalide : erreur générique", r.status_code == 400 and not leaks(r.text), r.text[:120])
    r = requests.post(f"{base}/auth/login", data="x" * 50_000, headers={"Content-Type": "application/json"}, timeout=10)
    record("DAST", "Corps > 16 Ko refusé (413)", r.status_code == 413, str(r.status_code))
    return bookie


# ---------------------------------------------------------------- Fuzzing

NASTY = ["", " ", "\x00", "\u202e", "😀" * 50, "A" * 5000, "%s%s%n", "{{7*7}}", "${jndi:ldap://x}",
         "' OR '1'='1", "x'); DROP TABLE users; --", "1 UNION SELECT password_hash FROM users",
         "../../../../etc/passwd", "<script>alert(1)</script>", "NaN", "-0", "1e309"]
NUMS = [0, -1, 1, 2**31, 2**63, -(2**63), 10**30, 1.5, float("inf"), True, None, "100", [], {}]


def rand_value(rnd):
    c = rnd.random()
    if c < 0.35:
        return rnd.choice(NASTY)
    if c < 0.65:
        return rnd.choice(NUMS)
    if c < 0.8:
        return "".join(rnd.choice(string.printable) for _ in range(rnd.randint(0, 40)))
    if c < 0.9:
        return [rand_value(rnd) for _ in range(rnd.randint(0, 3))]
    return {rnd.choice(["a", "title", "$ne", "__proto__"]): rand_value(rnd)}


def fuzz(base, headers, iterations, seed):
    rnd = random.Random(seed)
    fields = ["title", "description", "min_stake_cents", "bookie_fee_bp", "closes_at", "invitees"]
    statuses, crashes, leaky = Counter(), [], []
    payloads = []
    for i in range(iterations):
        mode = rnd.random()
        if mode < 0.1:  # corps brut non JSON / binaire
            raw = bytes(rnd.getrandbits(8) for _ in range(rnd.randint(0, 200)))
            r = requests.post(f"{base}/bets", data=raw, headers={**headers, "Content-Type": "application/json"}, timeout=10)
            payloads.append(repr(raw[:40]))
        else:
            body = {"title": "Pari fuzz", "closes_at": int(time.time()) + 3600}
            for f in rnd.sample(fields, rnd.randint(1, len(fields))):
                body[f] = rand_value(rnd)
            if rnd.random() < 0.2:
                body[rnd.choice(["role", "status", "bookie_id", "id"])] = rand_value(rnd)
            try:
                data = json.dumps(body, allow_nan=True)
            except (TypeError, ValueError):
                continue
            payloads.append(data[:200])
            r = requests.post(f"{base}/bets", data=data, headers={**headers, "Content-Type": "application/json"}, timeout=10)
        statuses[r.status_code] += 1
        if r.status_code >= 500:
            crashes.append((payloads[-1], r.text[:200]))
        if leaks(r.text):
            leaky.append((payloads[-1], leaks(r.text)))
        # fuzz du chemin
        if i % 10 == 0:
            p = rnd.choice(NASTY + [str(n) for n in NUMS])
            r = requests.get(f"{base}/bets/{requests.utils.quote(str(p), safe='')}", headers=headers, timeout=10)
            statuses[r.status_code] += 1
            if r.status_code >= 500:
                crashes.append(("GET /bets/" + p[:40], r.text[:200]))
    record("Fuzzing", f"{iterations} entrées aléatoires sur POST /bets : aucune erreur 500", not crashes,
           f"codes={dict(statuses)} ; crashs={crashes[:3]}")
    record("Fuzzing", "Aucune réponse ne révèle la structure interne", not leaky, str(leaky[:3]))
    return statuses


# ---------------------------------------------------------------- IAST

LITERAL = re.compile(r"'(?:[^']|'')*'")
DANGEROUS = re.compile(r"\b(DROP|UNION|ATTACH|ALTER)\b|--|/\*", re.I)


def iast(log_path):
    stmts = [ln for ln in Path(log_path).read_text(encoding="utf-8").splitlines() if "toutbet.iast" in ln]
    injected = [s for s in stmts if DANGEROUS.search(LITERAL.sub("''", s.split("stmt=", 1)[-1]))]
    record("IAST", f"{len(stmts)} requêtes SQL tracées : aucune charge utile interprétée comme du SQL",
           not injected, str(injected[:3]))
    unhandled = [ln for ln in Path(log_path).read_text(encoding="utf-8").splitlines() if "unhandled_error" in ln]
    record("IAST", "Aucune exception non gérée côté serveur", not unhandled, str(unhandled[:3]))
    per_req = Counter(re.search(r"request_id=(\w+)", s).group(1) for s in stmts if "request_id=" in s)
    worst = per_req.most_common(1)
    record("IAST", "Pas de requête HTTP déclenchant un nombre anormal de requêtes SQL (N+1 / DoS)",
           not worst or worst[0][1] < 200, f"max={worst}")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--iterations", type=int, default=500)
    ap.add_argument("--seed", type=int, default=42)
    args = ap.parse_args()
    REPORTS.mkdir(parents=True, exist_ok=True)
    log_path = REPORTS / "server.log"
    tmpdir = tempfile.mkdtemp()
    app, server, base = start_server(os.path.join(tmpdir, "dast.sqlite3"), log_path)
    try:
        bookie = dast(base, app)
        fuzz(base, bookie, args.iterations, args.seed)
    finally:
        server.shutdown()
        logging.shutdown()
    iast(log_path)

    lines = ["# Rapport DAST / IAST / Fuzzing — ToutBet'", "",
             f"Date : {time.strftime('%Y-%m-%d %H:%M')} — graine {args.seed}, {args.iterations} itérations", "",
             "| Type | Test | Résultat | Détail |", "|---|---|---|---|"]
    for r in results:
        d = str(r["detail"]).replace("|", "\\|").replace("\n", " ")[:180]
        lines.append(f"| {r['type']} | {r['test']} | {'OK' if r['ok'] else '**ÉCHEC**'} | {d} |")
    ok = sum(r["ok"] for r in results)
    lines += ["", f"**{ok}/{len(results)} tests réussis.**"]
    (REPORTS / "dast_report.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    print("\n".join(lines))
    return 0 if ok == len(results) else 1


if __name__ == "__main__":
    sys.exit(main())
