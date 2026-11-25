# ToutBet' — MVP sécurisé

Plateforme **mobile-first de paris personnalisés entre particuliers**, portée par **Youssef Bamou**.
Un *bookie* crée un pari (« Matis va-t-il réussir son créneau ? »), fixe une mise minimum et invite des
*parieurs*. L'argent est **séquestré** par la plateforme puis redistribué aux gagnants après validation du
résultat, une fois prélevées la commission du bookie et celle de la plateforme.

Ce dépôt contient le **socle technique de l'API** (atelier 1) et la **batterie de tests de sécurité**
(atelier 2) du module *Sécurité applicative pour les développeurs*.

## Démarrage rapide

```bash
python -m venv .venv && source .venv/bin/activate      # Windows : .venv\Scripts\activate
pip install -r requirements-dev.txt
cp .env.example .env                                     # puis remplacer les secrets
pytest -q                                                # 261 tests
python -m toutbet                                        # API sur http://127.0.0.1:5000
```

Créer un arbitre (administrateur) : `flask --app toutbet create-admin <nom>` (le mot de passe est demandé, jamais passé en argument).

## API

| Méthode | Route | Rôle |
|---|---|---|
| POST | `/auth/register`, `/auth/login`, `/auth/logout` | Comptes et jetons (Bearer, 1 h) |
| GET | `/wallet` | Solde et historique |
| POST | `/wallet/withdraw` | Retrait |
| POST | `/payments/webhook` | Dépôt confirmé par le prestataire de paiement (signé HMAC, idempotent) |
| POST / GET | `/bets`, `/bets/{id}` | Créer / consulter un pari (visible du bookie et des invités seulement) |
| POST | `/bets/{id}/invite` | Inviter des parieurs |
| POST | `/bets/{id}/wagers` | Miser (une mise par parieur, reçu signé) |
| POST | `/bets/{id}/result` | Le bookie propose le résultat après la clôture |
| POST | `/bets/{id}/dispute` | Un parieur conteste pendant le délai de contestation |
| POST | `/bets/{id}/settle` | Redistribution (l'admin tranche les litiges) |
| POST | `/bets/{id}/cancel` | Annulation par l'admin + remboursement |

Cycle d'un pari : `OPEN → PROPOSED → (DISPUTED) → SETTLED` ou `CANCELLED`.

## Organisation du dépôt

```
toutbet/                  Code de l'API (Flask + SQLite)
  ledger.py               SEUL point de modification des soldes + grand livre chaîné (HMAC)
  settlement.py           Calcul de la redistribution (centimes entiers, conservation garantie)
  security.py             Authentification, rate limiting, en-têtes de sécurité
  schemas.py              Validation stricte des entrées (pydantic)
  iast.py                 Instrumentation SQL pour les tests IAST
tests/
  test_abuse_stories.py   Abuse stories de l'atelier 1 automatisées (E2E API)
  test_concurrency.py     Paris simultanés d'un même utilisateur (risque de solde négatif)
  test_settlement.py      Tests unitaires et de propriété de la redistribution
security/
  dast_fuzz.py            DAST + IAST + Fuzzing de l'API de création de paris
  reports/                Rapports avant/après correction, stacktrace d'origine
load/
  locustfile.py           Test de charge : afflux de parieurs sur un même événement
  seed_event.py           Préparation des données de charge
docs/
  ATELIER1.md             Backlog, architecture et frontières de confiance, STRIDE
  ATELIER2.md             Semgrep, règles personnalisées, tests dynamiques, charge, solde négatif
  PROMPTS.md              Prompts utilisés pour générer le socle
```

## Sécurité

Voir [SECURITY.md](SECURITY.md). Aucun secret n'est versionné : ils sont lus dans les variables
d'environnement (`.env`, ignoré par Git) et l'application refuse de démarrer en production s'ils manquent.

> MVP pédagogique : le prestataire de paiement est simulé, et le serveur fourni sert uniquement au
> développement. En production, il faut utiliser gunicorn derrière un reverse proxy TLS, ainsi que Redis
> pour le rate limiting et PostgreSQL pour la base.
