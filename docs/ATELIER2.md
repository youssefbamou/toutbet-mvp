# Atelier 2 — Validation et tests offensifs

**Projet :** ToutBet' — plateforme mobile-first de paris personnalisés entre particuliers
**Membre du groupe :** Youssef Bamou
**Dépôt :** https://github.com/youssefbamou/toutbet-mvp

---

## Étape 1 — Analyse statique (Semgrep)

### Procédure suivie
```powershell
python -m venv .venv
.\.venv\Scripts\python -m pip install semgrep locust -r requirements.txt pytest requests
.\.venv\Scripts\semgrep login          # compte Semgrep créé (organisation personnelle, usage académique)
.\.venv\Scripts\semgrep scan --config p/python --config p/flask --config p/secrets
```
Le compte Semgrep a été créé avec un accès minimal : option « CLI — scan a local repository », sans connecter les
dépôts GitHub. L'activation du jeton CLI a échoué à plusieurs reprises (« Failed to login », problème réseau côté
poste Windows). Le scan a donc été lancé avec les règles publiques du registre Semgrep, et les résultats ont été
consultés dans la sortie de la CLI.

### Rapport Semgrep « Avant / Après »

| Analyse | Règles | Fichiers | Alertes |
|---|---|---|---|
| Semgrep (`p/python`, `p/flask`, `p/secrets`), code après corrections | 188 | 30 | **0** |
| Analyse statique complémentaire ruff + règles Bandit, **avant** correction | — | fichiers Python | **51** |
| Analyse statique complémentaire ruff + règles Bandit, **après** correction | — | fichiers Python | **0** |

<!-- img: 01_semgrep_scan.png | Sortie de Semgrep CLI : 188 règles, 30 fichiers, 0 alerte -->

Semgrep a été lancé **après** une première passe d'analyse statique. Celle-ci, faite avec ruff et les règles
Bandit `S` (`security/reports/ruff_AVANT_APRES.md`), avait relevé 51 alertes, toutes corrigées ou justifiées :

| Nb | Règle | Problème | Correction |
|---|---|---|---|
| 30 | S113 | Appels réseau `requests` sans timeout (blocage possible) | `timeout=10` partout |
| 6 | B904 | `raise` dans un `except` sans `from` : l'exception interne est chaînée | `raise ApiError(...) from None` |
| 1 | S101 | `assert` utilisé comme contrôle financier (supprimé par `python -O`) | Contrôle explicite qui lève une erreur (fail-safe) |
| 4 | E741, F841 | Variable ambiguë, variable inutilisée | Code nettoyé |
| 9 | S105, S311 | Mots de passe de test fictifs, `random` dans le fuzzing et la charge | Faux positifs justifiés, ignorés par fichier (`ruff.toml`) |
| 1 | E402 | Import après `sys.path.insert` dans un script autonome | Justifié |

### Règles personnalisées proposées (non écrites)

| # | Règle | Critères concrets de vérification |
|---|---|---|
| R1 | **Modification directe d'un solde** | Toute requête SQL contenant `UPDATE users SET balance_cents`, ou toute écriture dans la table `ledger`, **en dehors** de la fonction `register_transaction` (`toutbet/ledger.py`). |
| R2 | **Opération financière hors transaction verrouillée** | Tout appel à `register_transaction(...)` qui n'est pas à l'intérieur d'un bloc `with transaction(db):` : sans `BEGIN IMMEDIATE`, la vérification du solde et le débit ne sont plus atomiques (risque de solde négatif). |
| R3 | **Route mutante sans authentification** | Toute fonction décorée par `@bp.post`, `@bp.put`, `@bp.patch` ou `@bp.delete` sans `@login_required(...)`. Exceptions listées : `/auth/register`, `/auth/login`, `/payments/webhook` ; pour ce dernier, la présence de `hmac.compare_digest` est exigée. |
| R4 | **Montant monétaire non entier** | Un champ `*_cents` déclaré autrement qu'en `StrictInt` dans `schemas.py`, ou un `float(...)` appliqué à une variable `*_cents` ou `amount*`. |

---

## Étape 2 — Exploration dynamique (DAST, IAST, Fuzzing)

**Outil :** script [`security/dast_fuzz.py`](../security/dast_fuzz.py). Il démarre l'API sur un vrai serveur HTTP
en mode instrumenté, puis enchaîne les trois types de tests et produit un rapport markdown.

### Tests effectués (32), quel que soit le résultat

| Type | Test | Avant correction | Après correction |
|---|---|---|---|
| DAST | 6 en-têtes de sécurité (HSTS, CSP, nosniff, X-Frame-Options, Referrer-Policy, Cache-Control) | OK | OK |
| DAST | En-tête `Server` sans numéro de version | **ÉCHEC** : `Werkzeug/3.1.9 Python/3.13.18` | OK : `ToutBet` |
| DAST | CORS : origine tierce non autorisée | OK | OK |
| DAST | Méthode TRACE refusée | OK (405) | OK |
| DAST | 6 routes protégées appelées sans jeton (401 attendu) | OK | OK |
| DAST | 5 jetons forgés (vide, `null`, injection SQL, aléatoire, traversée de chemin) | OK (401) | OK |
| DAST | IDOR : énumération de 20 identifiants de paris d'autrui | OK (404 partout) | OK |
| DAST | IDOR : mise sur un pari sans invitation | OK (404) | OK |
| DAST | Élévation de privilèges : annulation par un non-admin | OK (403) | OK |
| DAST | Webhook de paiement non signé | OK (401) | OK |
| DAST | 404, JSON invalide, corps de plus de 16 Ko : erreurs génériques | OK | OK |
| Fuzzing | 500 entrées aléatoires ou malformées sur `POST /bets` et 50 sur `GET /bets/{id}` (types incohérents, nombres extrêmes, NaN, octets binaires, Unicode, injections SQL / SSTI / Log4Shell / XSS / traversée de chemin, champs interdits `role`, `status`, `bookie_id`) | **ÉCHEC** : 4 erreurs 500 | OK : 0 erreur 500 |
| Fuzzing | Aucune réponse ne révèle la structure interne | OK | OK |
| IAST | Plus de 600 requêtes SQL tracées : aucune charge utile interprétée comme du SQL | OK | OK |
| IAST | Aucune exception non gérée côté serveur | **ÉCHEC** : 4 `OverflowError` | OK |
| IAST | Pas de requête HTTP déclenchant un nombre anormal de requêtes SQL | OK (max 7) | OK |

Rapports complets : `security/reports/dast_report_AVANT.md` (29/32) et `security/reports/dast_report_APRES.md` (32/32).

### Logs serveur et stacktraces
Extrait de `security/reports/stacktrace_AVANT.log` :
```
ERROR toutbet unhandled_error request_id=bf210d0b27b8130b path=/bets/1000000000000000000000000000000
Traceback (most recent call last):
  File ".../toutbet/routes.py", line 241, in get_bet
    return jsonify(_bet_json(db, _bet_visible(db, bet_id)))
  File ".../toutbet/routes.py", line 48, in _bet_visible
    bet = db.execute("SELECT * FROM bets WHERE id = ?", (bet_id,)).fetchone()
OverflowError: Python int too large to convert to SQLite INTEGER
```

### Informations sur la structure interne dans les messages renvoyés
- **Corps des réponses :** aucune fuite. Même pendant le crash, le client ne recevait que
  `{"error":"internal_error","request_id":"bf210d0b27b8130b"}`. La stacktrace reste dans les logs serveur, et
  l'identifiant permet de la retrouver.
- **En-tête HTTP :** fuite des versions exactes (`Server: Werkzeug/3.1.9 Python/3.13.18`).
- **Logs IAST :** les traces SQL contiennent le hash des jetons de session. Ce hash ne permet pas de s'authentifier,
  et la configuration interdit ce mode en production.

---

## Étape 3 — Tests E2E et charge

### Chemins des fichiers de tests automatisés dans le dépôt
| Type | Fichier |
|---|---|
| Abuse stories de l'atelier 1 automatisées (12 abuse stories, environ 50 cas) | `tests/test_abuse_stories.py` |
| Paris simultanés, risque de solde négatif, base verrouillée sous charge | `tests/test_concurrency.py` |
| Redistribution des gains (tests unitaires et 200 cas aléatoires de conservation) | `tests/test_settlement.py` |
| DAST / IAST / Fuzzing | `security/dast_fuzz.py` |
| Test de charge Locust | `load/locustfile.py` (données : `load/seed_event.py`) |

Lancement : `pytest -q` → **262 tests réussis**, sous Linux comme sous Windows.

<!-- img: 08_pytest_262_windows.png | Exécution des 262 tests automatisés sur le poste Windows -->

### Test de charge Locust — scénario
Une « finale » : un bookie ouvre un pari, puis **500 parieurs invités** arrivent en même temps (50 nouveaux par
seconde). Chacun se connecte, consulte le pari, consulte son portefeuille et mise.
```powershell
python -m toutbet                                   # terminal 1 : l'API
python load\seed_event.py --users 500               # terminal 2 : 500 parieurs crédités et invités
locust -f load\locustfile.py --host http://127.0.0.1:5000   # puis http://localhost:8089
```

### Premier passage : 40 à 45 % d'échecs
<!-- img: 02_locust_AVANT_statistiques.png | Avant correction : statistiques (Failures 40 %) -->
<!-- img: 03_locust_AVANT_rps.png | Avant correction : requêtes par seconde et échecs par seconde -->
<!-- img: 04_locust_AVANT_temps_reponse.png | Avant correction : temps de réponse (médiane et 95e centile) -->
<!-- img: 06_locust_AVANT_echecs_1.png | Avant correction : détail des échecs (1/2) -->
<!-- img: 07_locust_AVANT_echecs_2.png | Avant correction : détail des échecs (2/2) -->

| Erreur observée | Nombre | Cause |
|---|---|---|
| `ConnectionRefusedError` (WinError 10061) | environ 100 | Au démarrage, le serveur de développement est saturé et refuse des connexions. |
| `OSError` (WinError 10048) « une seule utilisation de chaque adresse de socket » | plus de 50 000 | Le serveur de développement Werkzeug **ferme la connexion après chaque requête** (comportement voulu par Werkzeug). Chaque requête ouvre donc une nouvelle connexion TCP, et Windows **épuise ses ports**. C'est un déni de service par épuisement de ressources. |
| `500 INTERNAL SERVER ERROR` sur `POST /bets/{id}/wagers` | 17 | Sous contention, une mise attend le verrou d'écriture SQLite (temps maximal mesuré : **32 764 ms**, pour un délai d'attente de 30 s), puis échoue en `database is locked`. Cela produisait une erreur 500. |

### Corrections apportées
| Défaut | Correction | Test de non-régression |
|---|---|---|
| Erreur 500 après 30 s d'attente du verrou | Attente bornée à 5 s (`TOUTBET_DB_BUSY_TIMEOUT_MS`), puis réponse **503 + `Retry-After: 1`**. La transaction est annulée, donc **aucun débit partiel**. | `test_locked_database_returns_503_not_500` |
| Une connexion TCP par requête | Lancement par **waitress**, un serveur WSGI de production compatible Windows : connexions keep-alive et pool de 16 threads. Le serveur de développement reste un repli. | Second passage Locust |

<!-- img: 09_serveur_waitress.png | API relancée avec waitress -->

### Second passage, après correction : 0 % d'échec
<!-- img: 11_locust_APRES_statistiques.png | Après correction : statistiques (Failures 0 %) -->
<!-- img: 12_locust_APRES_rps.png | Après correction : environ 365 requêtes/s stables, aucun échec -->
<!-- img: 13_locust_APRES_temps_reponse.png | Après correction : temps de réponse revenus sous 0,5 s après la montée en charge -->
<!-- img: 14_locust_APRES_utilisateurs.png | Après correction : 500 utilisateurs simultanés -->
<!-- img: 15_locust_APRES_echecs.png | Après correction : seules restent des réponses 503 contrôlées -->

| Indicateur (500 utilisateurs) | Avant | Après |
|---|---|---|
| Taux d'échec | 40 à 45 % | **0 %** (17 réponses 503 contrôlées sur environ 12 800 mises, soit 0,1 %) |
| Erreurs 500 | 17 | **0** |
| Erreurs de connexion ou de socket | plus de 50 000 | **0** |
| Débit | 220 à 360 requêtes/s, instable | **environ 365 requêtes/s, stable** |
| Temps de réponse médian (régime établi) | jusqu'à plusieurs secondes | **environ 100 ms** |
| Temps de réponse 95e centile (global) | 2 800 ms | **600 ms** |

**Analyse.** La phase de connexion reste la plus lente : 4,4 s en médiane quand 500 personnes se connectent en
10 secondes. C'est voulu. Le hachage scrypt des mots de passe est volontairement coûteux pour résister à la force
brute, mais ce coût devient un point de saturation lors d'un afflux massif. En production, il faudrait plusieurs
instances derrière un répartiteur de charge, PostgreSQL à la place de SQLite (qui n'accepte qu'un seul écrivain à
la fois, d'où les quelques 503 restantes) et le rate limiting par IP réactivé (désactivé pour ce test, sinon Locust,
qui utilise une seule IP, serait bloqué).

### Le même utilisateur peut-il dépenser plus que son solde avec des paris simultanés ?

**Oui, le risque est réel si le code est écrit naïvement.** Nous l'avons démontré
(`test_naive_implementation_lets_user_overspend`) : avec la logique « lire le solde → vérifier → écrire », 10 paris
de 10 € lancés en même temps avec un solde de 10 € ont été **tous acceptés**, sur 5 exécutions sur 5. Le parieur a
donc dépensé 100 € avec 10 €. C'est une *race condition* de type TOCTOU (*time of check / time of use*) : toutes
les requêtes lisent le même solde avant que la première n'écrive.

**Dans ToutBet', le risque est neutralisé.** Les tests sur un vrai serveur HTTP multithread le vérifient :
- 50 paris de 10 € lancés simultanément avec 100 € de solde : **exactement 10 acceptés**, 40 refusés, solde final de
  0 €, séquestre de 100 € (aucun centime créé ni perdu) ;
- 30 mises simultanées sur le **même** pari : **une seule acceptée** ;
- 20 retraits simultanés de 10 € avec 50 € de solde : **5 acceptés**, solde final de 0 € ;
- sous la charge Locust (500 utilisateurs), aucune incohérence de solde : les mises refusées pour surcharge (503)
  ne débitent rien.

Trois défenses superposées :
1. **Débit conditionnel atomique** : `UPDATE users SET balance_cents = balance_cents - ? WHERE id = ? AND balance_cents >= ?`.
   La vérification et l'écriture forment une seule instruction ; si aucune ligne n'est modifiée, le pari est refusé.
2. **Transaction `BEGIN IMMEDIATE`** : les écritures sont sérialisées, et toutes les vérifications (pari ouvert,
   invitation, mise minimum) sont refaites à l'intérieur de la transaction.
3. **Contrainte en base `CHECK (balance_cents >= 0)`** : même un bug futur ne pourrait pas rendre un solde négatif.

En production sur PostgreSQL avec plusieurs instances, la même règle s'applique : un `UPDATE` conditionnel ou un
`SELECT ... FOR UPDATE` dans une transaction, plus la contrainte `CHECK`. Un verrou en mémoire de l'application ne
suffirait pas, car il ne protège qu'une seule instance.
