# Atelier 2 — Validation et tests offensifs

**Projet :** ToutBet' — **Porteur :** Youssef Bamou — **Membres du groupe :** _à compléter_
**Dépôt :** https://github.com/youssefbamou/toutbet-mvp

---

## Étape 1 — Analyse statique (Semgrep)

### Procédure
```bash
python -m venv .venv && source .venv/bin/activate
pip install semgrep
semgrep login                     # relie la CLI au compte Semgrep (accès minimal au dépôt)
semgrep ci                        # scan envoyé sur le tableau de bord Semgrep
# ou, sans envoi : semgrep scan --config p/python --config p/flask --config p/secrets
```
Le même scan, sans compte, tourne aussi à chaque push dans GitHub Actions (`.github/workflows/security.yml`).

### Rapport Semgrep « Avant / Après »
> _À compléter avec les résultats de votre compte Semgrep (copie d'écran du tableau de bord ou sortie de la CLI)._

| Règle Semgrep | Fichier:ligne | Gravité | Avant | Correction ou justification | Après |
|---|---|---|---|---|---|
| | | | | | |

### Analyse statique complémentaire (ruff + règles Bandit)
Avant correction : **51 alertes**. Après : **0**. Le détail se trouve dans [`security/reports/ruff_AVANT_APRES.md`](../security/reports/ruff_AVANT_APRES.md). Corrections principales :
- appels réseau sans timeout ;
- exceptions internes chaînées vers la réponse (`raise ... from None`) ;
- `assert` utilisé comme contrôle financier (désactivé par `python -O`), remplacé par un contrôle explicite.

### Règles personnalisées proposées (non écrites)

| # | Règle | Critères concrets de vérification |
|---|---|---|
| R1 | **Modification directe d'un solde** | Toute requête SQL contenant `UPDATE users SET balance_cents` (ou une affectation de `balance_cents`) **en dehors** de la fonction `register_transaction` de `toutbet/ledger.py` déclenche une alerte. Toute écriture dans la table `ledger` hors de cette même fonction aussi. |
| R2 | **Opération financière hors transaction verrouillée** | Tout appel à `register_transaction(...)` qui n'est pas lexicalement à l'intérieur d'un bloc `with transaction(db):` déclenche une alerte : sans `BEGIN IMMEDIATE`, la vérification du solde et le débit ne sont plus atomiques. |
| R3 | **Route mutante sans authentification** | Toute fonction décorée par `@bp.post`, `@bp.put`, `@bp.patch` ou `@bp.delete` qui n'est pas aussi décorée par `@login_required(...)` déclenche une alerte. Seules exceptions autorisées, explicitement listées : `/auth/register`, `/auth/login`, `/payments/webhook`. Pour ce dernier, la règle exige la présence de `hmac.compare_digest` dans le corps de la fonction. |
| R4 (bonus) | **Montant monétaire non entier** | Un champ dont le nom se termine par `_cents` déclaré avec un type autre que `StrictInt` dans `schemas.py`, ou toute utilisation de `float(` sur une variable `*_cents` / `amount*`, déclenche une alerte. |

---

## Étape 2 — Exploration dynamique (DAST, IAST, Fuzzing)

**Outil :** script maison [`security/dast_fuzz.py`](../security/dast_fuzz.py). Il démarre l'API sur un vrai
serveur HTTP en mode instrumenté puis enchaîne les trois types de tests. Il génère
`security/reports/dast_report.md` et les logs serveur. OWASP ZAP peut compléter en scan de base :
`docker run -t ghcr.io/zaproxy/zaproxy:stable zap-baseline.py -t http://host.docker.internal:5000/health`.

### Tests effectués (32), quel que soit le résultat

| Type | Test | Avant correction | Après correction |
|---|---|---|---|
| DAST | 6 en-têtes de sécurité (HSTS, CSP, nosniff, X-Frame-Options, Referrer-Policy, Cache-Control) | OK | OK |
| DAST | En-tête `Server` sans version | **ÉCHEC** : `Werkzeug/3.1.9 Python/3.13.18` | OK : `ToutBet` |
| DAST | CORS : origine tierce non autorisée | OK | OK |
| DAST | Méthode TRACE refusée | OK (405) | OK |
| DAST | 6 routes protégées appelées sans jeton (401 attendu) | OK | OK |
| DAST | 5 jetons forgés (vide, `null`, injection SQL, aléatoire, chemin) | OK (401) | OK |
| DAST | IDOR : énumération de 20 identifiants de paris d'autrui | OK (404 partout) | OK |
| DAST | IDOR : mise sur un pari sans invitation | OK (404) | OK |
| DAST | Élévation : annulation par un non-admin | OK (403) | OK |
| DAST | Webhook de paiement non signé | OK (401) | OK |
| DAST | 404, JSON invalide, corps de plus de 16 Ko : erreurs génériques | OK | OK |
| Fuzzing | 500 entrées aléatoires ou malformées sur `POST /bets` (+ 50 sur `GET /bets/{id}`) : types incohérents, nombres extrêmes, NaN/Infinity, octets binaires, Unicode, injections SQL / SSTI / Log4Shell / XSS / traversée de chemin, champs interdits (`role`, `status`, `bookie_id`) | **ÉCHEC** : 4 erreurs 500 | OK : 0 erreur 500 |
| Fuzzing | Aucune réponse ne révèle la structure interne | OK | OK |
| IAST | 614 requêtes SQL tracées : aucune charge utile interprétée comme du SQL | OK | OK |
| IAST | Aucune exception non gérée côté serveur | **ÉCHEC** : 4 `OverflowError` | OK |
| IAST | Aucune requête HTTP ne déclenche un nombre anormal de requêtes SQL | OK (max 7) | OK |

Rapports complets : [`dast_report_AVANT.md`](../security/reports/dast_report_AVANT.md) et [`dast_report_APRES.md`](../security/reports/dast_report_APRES.md).

### Logs serveur et stacktraces
Extrait complet : [`security/reports/stacktrace_AVANT.log`](../security/reports/stacktrace_AVANT.log).
```
ERROR toutbet unhandled_error request_id=bf210d0b27b8130b path=/bets/1000000000000000000000000000000
Traceback (most recent call last):
  File ".../toutbet/routes.py", line 241, in get_bet
    return jsonify(_bet_json(db, _bet_visible(db, bet_id)))
  File ".../toutbet/routes.py", line 48, in _bet_visible
    bet = db.execute("SELECT * FROM bets WHERE id = ?", (bet_id,)).fetchone()
OverflowError: Python int too large to convert to SQLite INTEGER
```

### Informations sur la structure interne dans les réponses
- **Corps des réponses :** aucune fuite. Même lors du crash, le client recevait seulement
  `{"error":"internal_error","request_id":"bf210d0b27b8130b"}`. La stacktrace restait dans les logs serveur, et l'identifiant
  permet de retrouver le log correspondant.
- **En-tête HTTP :** fuite des versions exactes (`Server: Werkzeug/3.1.9 Python/3.13.18`).
- **Logs IAST :** les traces SQL contiennent le hash des jetons de session. Ce hash ne permet pas de s'authentifier,
  mais ces traces ne doivent jamais exister en production : la configuration refuse de démarrer si
  `TOUTBET_IAST_TRACE=1` en production.

### Corrections effectuées
| Défaut | Correction | Test de non-régression |
|---|---|---|
| Erreur 500 sur un identifiant supérieur à 2⁶³ (`OverflowError`), exploitable pour remplir les logs | Identifiants bornés dans toutes les routes : `<int(max=9223372036854775807):bet_id>` → 404 | `TestFuzzingRegressions::test_huge_bet_id_is_404_not_500` |
| Versions exposées dans `Server` | Gestionnaire de requêtes du serveur de développement : `Server: ToutBet` (`toutbet/devserver.py`) | `TestFuzzingRegressions::test_server_header_hides_versions` |

---

## Étape 3 — Tests E2E et charge

### Chemins des fichiers de tests automatisés dans le dépôt
| Type | Fichier |
|---|---|
| Abuse stories automatisées (12 abuse stories, ~50 cas) | `tests/test_abuse_stories.py` |
| Paris simultanés / risque de solde négatif | `tests/test_concurrency.py` |
| Redistribution (unitaires + 200 cas aléatoires de conservation) | `tests/test_settlement.py` |
| DAST / IAST / Fuzzing | `security/dast_fuzz.py` |
| Charge (Locust) | `load/locustfile.py` (+ données : `load/seed_event.py`) |

Lancement : `pytest -q` → **261 tests réussis**.

### Test de charge Locust
```bash
export TOUTBET_RATE_LIMIT_PER_MINUTE=1000000 TOUTBET_PAYMENT_WEBHOOK_SECRET=secret-local
python -m toutbet                                  # terminal 1
python load/seed_event.py --users 500              # terminal 2 (même secret exporté)
locust -f load/locustfile.py --host http://127.0.0.1:5000
# ouvrir http://localhost:8089 : 500 utilisateurs, montée de 50/s
```
Scénario : 500 parieurs invités sur la même « finale », qui consultent le pari, consultent leur portefeuille et misent.
Variante : relancer **sans** désactiver le rate limiting pour vérifier que l'API répond 429 au lieu de s'effondrer.

> _Copies d'écran de l'interface Web Locust : à insérer ici._

### Le même utilisateur peut-il dépenser plus que son solde avec des paris simultanés ?

**Oui, le risque est réel si le code est écrit naïvement**, et nous l'avons démontré
(`test_naive_implementation_lets_user_overspend`). Avec une logique « lire le solde → vérifier → écrire »,
10 paris de 10 € lancés en même temps avec un solde de 10 € ont été **tous acceptés**, sur 5 exécutions sur 5.
Le parieur a donc dépensé 100 € avec 10 €. C'est une *race condition* de type TOCTOU (*time of check / time of use*) :
toutes les requêtes lisent le même solde avant que la première n'écrive.

**Dans ToutBet', le risque est neutralisé**, ce que vérifient les tests sur un vrai serveur HTTP multithread :
- 50 paris de 10 € lancés simultanément avec 100 € de solde : **exactement 10 acceptés**, 40 refusés (`insufficient_funds`),
  solde final de 0 €, et séquestre de 100 € (conservation de l'argent vérifiée) ;
- 30 mises simultanées sur le **même** pari : **1 seule acceptée** ;
- 20 retraits simultanés de 10 € avec 50 € de solde : **5 acceptés**, solde final de 0 €.

Trois défenses superposées :
1. **Débit conditionnel atomique** : `UPDATE users SET balance_cents = balance_cents - ? WHERE id = ? AND balance_cents >= ?`.
   La vérification et l'écriture forment une seule instruction, et si 0 ligne est modifiée, le pari est refusé.
2. **Transaction `BEGIN IMMEDIATE`** : les écritures sont sérialisées, et toutes les vérifications (pari ouvert, invitation,
   mise minimum) sont refaites à l'intérieur de la transaction.
3. **Contrainte en base `CHECK (balance_cents >= 0)`** : même un bug applicatif futur ne pourrait pas rendre un solde négatif.

En production sur PostgreSQL avec plusieurs instances, la même règle s'applique : un `UPDATE` conditionnel ou un
`SELECT ... FOR UPDATE` dans une transaction, plus la contrainte `CHECK`. Un verrou en mémoire de l'application ne
suffirait pas, car il ne protège qu'une seule instance.
