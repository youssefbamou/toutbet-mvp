"""Automatisation des Abuse Stories de l'atelier 1 (une classe par abuse story).

Chaque test joue le rôle de l'attaquant et vérifie que l'attaque échoue.
"""
import sqlite3

import pytest

from toutbet.db import connect


# AS1 — « En tant qu'attaquant, je veux deviner le mot de passe d'un parieur par force brute
#        pour vider son compte. »
class TestAS01BruteForce:
    def test_login_locked_after_repeated_failures(self, api, client):
        victim = api.user()
        codes = [client.post("/auth/login", json={"username": victim["name"], "password": f"faux-{i}"}).status_code
                 for i in range(5)]
        assert codes == [401] * 5
        # même avec le BON mot de passe, le compte est temporairement verrouillé
        r = client.post("/auth/login", json={"username": victim["name"], "password": "MotDePasse-Test-123"})
        assert r.status_code == 429

    def test_same_error_for_unknown_user_and_bad_password(self, api, client):
        u = api.user()
        a = client.post("/auth/login", json={"username": u["name"], "password": "mauvais"})
        b = client.post("/auth/login", json={"username": "inexistant", "password": "mauvais"})
        assert a.status_code == b.status_code == 401
        assert a.json == b.json  # pas d'énumération des comptes

    def test_forged_or_expired_token_rejected(self, api, client, clock):
        u = api.user()
        assert client.get("/wallet", headers={"Authorization": "Bearer " + "A" * 43}).status_code == 401
        clock.advance(3601)
        assert client.get("/wallet", headers=u["h"]).status_code == 401

    def test_logout_invalidates_token(self, api, client):
        u = api.user()
        client.post("/auth/logout", headers=u["h"])
        assert client.get("/wallet", headers=u["h"]).status_code == 401


# AS2 — « En tant que fraudeur, je veux forger ou rejouer une notification de paiement
#        pour créditer mon compte sans payer. »
class TestAS02FakeDeposit:
    def test_forged_signature_rejected(self, api, client):
        u = api.user()
        body = b'{"event_id":"evt_12345678","type":"payment.succeeded","username":"%s","amount_cents":100000}' % u["name"].encode()
        r = client.post("/payments/webhook", data=body, headers={"Content-Type": "application/json", "X-Signature": "00" * 32})
        assert r.status_code == 401
        assert api.balance(u) == 0

    def test_replayed_event_credited_once(self, api):
        u = api.user()
        assert api.deposit(u["name"], 5000, event_id="evt_replay01").json["status"] == "credited"
        assert api.deposit(u["name"], 5000, event_id="evt_replay01").json["status"] == "already_processed"
        assert api.balance(u) == 5000

    def test_no_self_service_credit_endpoint(self, api, client):
        u = api.user()
        for path in ("/wallet/deposit", "/wallet/credit", "/admin/credit"):
            assert client.post(path, json={"amount_cents": 100000}, headers=u["h"]).status_code in (404, 405)


# AS3 — « En tant que bookie malhonnête, je veux fixer une commission abusive ou créer un pari
#        déjà clos pour piéger les parieurs. »
class TestAS03AbusiveBet:
    def test_bookie_fee_capped(self, api, client, clock):
        b = api.user()
        r = client.post("/bets", json={"title": "Pari", "closes_at": clock() + 3600, "bookie_fee_bp": 5000}, headers=b["h"])
        assert r.status_code == 422

    def test_closing_date_in_past_rejected(self, api, client, clock):
        b = api.user()
        r = client.post("/bets", json={"title": "Pari", "closes_at": clock() - 10}, headers=b["h"])
        assert r.status_code == 422


# AS4 — « En tant que curieux, je veux accéder à un pari privé ou y miser sans être invité. »
class TestAS04PrivateBetAccess:
    def test_non_invited_cannot_read_or_wager(self, api, client):
        bookie, outsider = api.user(), api.user(deposit_cents=5000)
        bet = api.bet(bookie)
        assert client.get(f"/bets/{bet}", headers=outsider["h"]).status_code == 404
        assert api.wager(outsider, bet).status_code == 404
        assert api.balance(outsider) == 5000

    def test_cannot_see_other_wallet(self, api, client):
        # pas de paramètre user_id : le portefeuille est toujours celui du jeton
        a = api.user(deposit_cents=100)
        api.user(deposit_cents=999)
        assert client.get("/wallet?user_id=999", headers=a["h"]).json["balance_cents"] == 100


# AS5 — « En tant que parieur malveillant, je veux miser un montant négatif ou supérieur à mon
#        solde pour créer de l'argent. »
class TestAS05MoneyCreation:
    @pytest.mark.parametrize("amount", [-1000, 0, "1000", 10.5, 10**12])
    def test_invalid_amounts_rejected(self, api, amount):
        bookie, p = api.user(), api.user(deposit_cents=5000)
        bet = api.bet(bookie, [p])
        r = api.wager(p, bet, amount=amount)
        assert r.status_code in (409, 422)
        assert api.balance(p) == 5000

    def test_wager_above_balance_rejected(self, api):
        bookie, p = api.user(), api.user(deposit_cents=500)
        bet = api.bet(bookie, [p])
        assert api.wager(p, bet, amount=1000).json["error"] == "insufficient_funds"
        assert api.balance(p) == 500

    def test_below_min_stake_rejected(self, api):
        bookie, p = api.user(), api.user(deposit_cents=5000)
        bet = api.bet(bookie, [p], min_stake_cents=2000)
        assert api.wager(p, bet, amount=1000).json["error"] == "below_min_stake"

    def test_withdraw_more_than_balance_rejected(self, api, client):
        u = api.user(deposit_cents=1000)
        r = client.post("/wallet/withdraw", json={"amount_cents": 1001}, headers=u["h"])
        assert r.status_code == 409 and api.balance(u) == 1000

    def test_database_refuses_negative_balance(self, app):
        conn = connect(app.config["DATABASE"])
        conn.execute("INSERT INTO users (username, password_hash, created_at) VALUES ('x', 'h', 0)")
        with pytest.raises(sqlite3.IntegrityError):
            conn.execute("UPDATE users SET balance_cents = -1 WHERE username = 'x'")
        conn.close()


# AS6 — « En tant que parieur malveillant, je veux modifier mon pari après sa clôture
#        pour remporter la mise. » (exemple de l'énoncé)
class TestAS06ModifyAfterClose:
    def test_no_wager_after_close(self, api, clock):
        bookie, p = api.user(), api.user(deposit_cents=5000)
        bet = api.bet(bookie, [p], closes_in=120)
        clock.advance(121)
        assert api.wager(p, bet).json["error"] == "bet_closed"

    def test_cannot_place_second_wager_to_switch_side(self, api):
        bookie, p = api.user(), api.user(deposit_cents=5000)
        bet = api.bet(bookie, [p])
        assert api.wager(p, bet, "YES").status_code == 201
        assert api.wager(p, bet, "NO").json["error"] == "already_wagered"

    def test_no_update_route(self, api, client):
        bookie, p = api.user(), api.user(deposit_cents=5000)
        bet = api.bet(bookie, [p])
        api.wager(p, bet)
        for method in (client.put, client.patch, client.delete):
            assert method(f"/bets/{bet}/wagers", json={"outcome": "NO"}, headers=p["h"]).status_code == 405

    def test_database_refuses_wager_update(self, api, app):
        bookie, p = api.user(), api.user(deposit_cents=5000)
        bet = api.bet(bookie, [p])
        api.wager(p, bet, "YES")
        conn = connect(app.config["DATABASE"])
        with pytest.raises(sqlite3.IntegrityError):
            conn.execute("UPDATE wagers SET outcome = 'NO'")
        conn.close()


# AS7 — « En tant que parieur ou bookie malhonnête, je veux manipuler le résultat
#        (le déclarer à la place du bookie, avant la fin, ou parier sur mon propre pari). »
class TestAS07ResultManipulation:
    def test_only_bookie_can_propose_result(self, api, client, clock):
        bookie, p = api.user(), api.user(deposit_cents=5000)
        bet = api.bet(bookie, [p], closes_in=120)
        clock.advance(121)
        assert client.post(f"/bets/{bet}/result", json={"outcome": "YES"}, headers=p["h"]).status_code == 403

    def test_result_not_before_close(self, api, client):
        bookie, p = api.user(), api.user()
        bet = api.bet(bookie, [p])
        r = client.post(f"/bets/{bet}/result", json={"outcome": "YES"}, headers=bookie["h"])
        assert r.json["error"] == "bet_not_closed"

    def test_bookie_cannot_bet_on_own_bet(self, api, client):
        bookie = api.user(deposit_cents=5000)
        bet = api.bet(bookie)
        assert client.post(f"/bets/{bet}/wagers", json={"outcome": "YES", "amount_cents": 500},
                           headers=bookie["h"]).status_code == 403

    def test_result_cannot_be_changed_once_proposed(self, api, client, clock):
        bookie, p = api.user(), api.user()
        bet = api.bet(bookie, [p], closes_in=120)
        clock.advance(121)
        client.post(f"/bets/{bet}/result", json={"outcome": "YES"}, headers=bookie["h"])
        r = client.post(f"/bets/{bet}/result", json={"outcome": "NO"}, headers=bookie["h"])
        assert r.json["error"] == "invalid_state"

    def test_cannot_settle_during_dispute_window(self, api, client, clock):
        bookie, p = api.user(), api.user(deposit_cents=1000)
        bet = api.bet(bookie, [p], closes_in=120)
        api.wager(p, bet)
        clock.advance(121)
        client.post(f"/bets/{bet}/result", json={"outcome": "NO"}, headers=bookie["h"])
        assert client.post(f"/bets/{bet}/settle", json={}, headers=bookie["h"]).json["error"] == "dispute_window_open"


# AS8 — « En tant que perdant, je veux nier avoir effectué mon pari (répudiation) /
#        contester sans fin pour bloquer la redistribution. »
class TestAS08Repudiation:
    def test_wager_receipt_and_ledger_chain(self, api, app, client):
        from toutbet.ledger import sign_receipt, verify_chain
        bookie, p = api.user(), api.user(deposit_cents=5000)
        bet = api.bet(bookie, [p])
        r = api.wager(p, bet, "NO", 1500)
        detail = client.get(f"/bets/{bet}", headers=p["h"]).json["my_wager"]
        assert detail["receipt"] == r.json["receipt"]
        conn = connect(app.config["DATABASE"])
        uid = conn.execute("SELECT id FROM users WHERE username = ?", (p["name"],)).fetchone()["id"]
        assert r.json["receipt"] == sign_receipt(app.config["SECRET_KEY"], "wager", bet, uid, "NO", 1500, r.json["created_at"])
        assert verify_chain(conn, app.config["SECRET_KEY"])
        conn.close()

    def test_ledger_is_append_only(self, api, app):
        api.user(deposit_cents=5000)
        conn = connect(app.config["DATABASE"])
        with pytest.raises(sqlite3.IntegrityError):
            conn.execute("DELETE FROM ledger")
        with pytest.raises(sqlite3.IntegrityError):
            conn.execute("UPDATE ledger SET amount_cents = 999999")
        conn.close()

    def test_dispute_then_only_admin_settles(self, api, client, clock):
        bookie, p, admin = api.user(), api.user(deposit_cents=1000), api.admin()
        bet = api.bet(bookie, [p], closes_in=120)
        api.wager(p, bet, "YES")
        clock.advance(121)
        client.post(f"/bets/{bet}/result", json={"outcome": "NO"}, headers=bookie["h"])
        assert client.post(f"/bets/{bet}/dispute", json={"reason": "Matis a réussi"}, headers=p["h"]).status_code == 200
        assert client.post(f"/bets/{bet}/dispute", json={"reason": "encore"}, headers=p["h"]).status_code == 409
        clock.advance(601)
        assert client.post(f"/bets/{bet}/settle", json={"outcome": "NO"}, headers=bookie["h"]).status_code == 403
        r = client.post(f"/bets/{bet}/settle", json={"outcome": "YES"}, headers=admin["h"])
        assert r.status_code == 200 and r.json["final_outcome"] == "YES"

    def test_non_participant_cannot_dispute(self, api, client, clock):
        bookie, p, other = api.user(), api.user(deposit_cents=1000), api.user()
        bet = api.bet(bookie, [p, other], closes_in=120)
        api.wager(p, bet)
        clock.advance(121)
        client.post(f"/bets/{bet}/result", json={"outcome": "NO"}, headers=bookie["h"])
        assert client.post(f"/bets/{bet}/dispute", json={"reason": "spam"}, headers=other["h"]).status_code == 403


# AS9 — « En tant que gagnant malin, je veux déclencher deux fois la redistribution
#        pour être payé deux fois. »
class TestAS09DoublePayout:
    def test_settle_only_once(self, api, client, clock):
        bookie, w, loser = api.user(), api.user(deposit_cents=1000), api.user(deposit_cents=1000)
        bet = api.bet(bookie, [w, loser], closes_in=120, bookie_fee_bp=500)
        api.wager(w, bet, "YES", 1000)
        api.wager(loser, bet, "NO", 1000)
        clock.advance(121)
        client.post(f"/bets/{bet}/result", json={"outcome": "YES"}, headers=bookie["h"])
        clock.advance(601)
        assert client.post(f"/bets/{bet}/settle", json={}, headers=w["h"]).status_code == 200
        assert client.post(f"/bets/{bet}/settle", json={}, headers=w["h"]).status_code == 409
        # cagnotte 2000 : plateforme 5 % = 100, bookie 5 % = 100, gagnant 1800
        assert api.balance(w) == 1800
        assert api.balance(bookie) == 100
        assert api.balance(loser) == 0

    def test_non_admin_cannot_override_outcome(self, api, client, clock):
        bookie, p = api.user(), api.user(deposit_cents=1000)
        bet = api.bet(bookie, [p], closes_in=120)
        api.wager(p, bet, "YES")
        clock.advance(121)
        client.post(f"/bets/{bet}/result", json={"outcome": "NO"}, headers=bookie["h"])
        clock.advance(601)
        assert client.post(f"/bets/{bet}/settle", json={"outcome": "YES"}, headers=p["h"]).status_code == 403


# AS10 — « En tant qu'utilisateur malveillant, je veux m'octroyer les droits administrateur
#         pour annuler ou trancher les paris à mon avantage. »
class TestAS10PrivilegeEscalation:
    def test_role_field_ignored_at_registration(self, client):
        r = client.post("/auth/register", json={"username": "pirate", "password": "MotDePasse-Test-123", "role": "admin"})
        assert r.status_code == 422  # champ inconnu refusé

    def test_user_cannot_cancel(self, api, client):
        bookie = api.user()
        bet = api.bet(bookie)
        assert client.post(f"/bets/{bet}/cancel", headers=bookie["h"]).status_code == 403

    def test_admin_cancel_refunds(self, api, client):
        bookie, p, admin = api.user(), api.user(deposit_cents=1000), api.admin()
        bet = api.bet(bookie, [p])
        api.wager(p, bet, amount=700)
        assert client.post(f"/bets/{bet}/cancel", headers=admin["h"]).status_code == 200
        assert api.balance(p) == 1000


# AS11 — « En tant qu'attaquant, je veux injecter du SQL ou provoquer des erreurs pour
#         découvrir la structure interne de l'application. »
class TestAS11InjectionAndLeaks:
    def test_sql_injection_in_title_is_stored_as_text(self, api, client):
        bookie = api.user()
        payload = "x'); DROP TABLE users; --"
        bet = api.bet(bookie, title=payload)
        assert client.get(f"/bets/{bet}", headers=bookie["h"]).json["title"] == payload
        assert client.get("/wallet", headers=bookie["h"]).status_code == 200

    def test_sql_injection_in_login(self, api, client):
        api.user("alice")
        r = client.post("/auth/login", json={"username": "alice' OR '1'='1", "password": "x' OR '1'='1"})
        assert r.status_code == 401

    @pytest.mark.parametrize("body", [b"{", b"[]", b"null", b'{"username": {"$ne": null}}', b"\xff\xfe"])
    def test_malformed_json_gives_generic_error(self, client, body):
        r = client.post("/auth/login", data=body, headers={"Content-Type": "application/json"})
        assert r.status_code in (400, 422)
        text = r.get_data(as_text=True)
        for leak in ("Traceback", "sqlite", "File \"", "werkzeug", "pydantic"):
            assert leak not in text

    def test_unhandled_error_hides_stacktrace(self, app, client):
        @app.get("/boom")
        def boom():
            raise RuntimeError("secret interne: /srv/toutbet/db.sqlite3")
        r = client.get("/boom")
        assert r.status_code == 500
        assert "secret interne" not in r.get_data(as_text=True)
        assert set(r.json) == {"error", "request_id"}

    def test_security_headers(self, client):
        r = client.get("/health")
        for h in ("Strict-Transport-Security", "Content-Security-Policy", "X-Content-Type-Options", "X-Frame-Options"):
            assert h in r.headers

    def test_oversized_body_rejected(self, api, client):
        u = api.user()
        r = client.post("/bets", data=b'{"title":"' + b"a" * 20000 + b'"}',
                        headers={**u["h"], "Content-Type": "application/json"})
        assert r.status_code == 413


# AS12 — « En tant qu'attaquant, je veux saturer l'API lors d'un événement majeur (DoS). »
class TestAS12DenialOfService:
    def test_rate_limit_per_ip(self, app, client):
        app.config["RATE_LIMIT_PER_MINUTE"] = 20
        codes = [client.get("/health").status_code for _ in range(25)]
        assert codes.count(429) == 5


# Non-régression des défauts trouvés par le fuzzing (atelier 2, étape 2)
class TestFuzzingRegressions:
    @pytest.mark.parametrize("bet_id", ["9223372036854775808", "1" + "0" * 30])
    def test_huge_bet_id_is_404_not_500(self, api, client, bet_id):
        u = api.user()
        assert client.get(f"/bets/{bet_id}", headers=u["h"]).status_code == 404
        assert client.post(f"/bets/{bet_id}/wagers", json={"outcome": "YES", "amount_cents": 100},
                           headers=u["h"]).status_code == 404

    def test_server_header_hides_versions(self, app):
        import threading
        import requests
        from toutbet.devserver import make_dev_server
        server = make_dev_server(app, "127.0.0.1", 0)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        try:
            r = requests.get(f"http://127.0.0.1:{server.server_port}/health", timeout=10)
            assert r.headers["Server"] == "ToutBet"
        finally:
            server.shutdown()
