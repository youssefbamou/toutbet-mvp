# Politique de sécurité — ToutBet'

## Signaler une vulnérabilité
N'ouvrez pas d'issue publique. Contactez le porteur du projet en privé, avec les étapes de reproduction.

## Mesures en place (résumé)
| Risque | Mesure | Où |
|---|---|---|
| Vol de compte | Mots de passe scrypt, verrouillage après 5 échecs, jetons aléatoires stockés hachés, expiration 1 h | `security.py` |
| Création d'argent / solde négatif | Débit conditionnel atomique dans `BEGIN IMMEDIATE`, `CHECK (balance_cents >= 0)`, centimes entiers | `ledger.py`, `db.py` |
| Faux dépôt | Webhook signé HMAC-SHA256, comparaison à temps constant, idempotence `event_id` | `routes.py` |
| Modification d'une mise | Aucune route de modification, triggers SQL d'immuabilité | `db.py` |
| Manipulation du résultat | Seul le bookie propose, après clôture ; délai de contestation ; arbitrage admin ; le bookie ne peut pas miser | `routes.py` |
| Répudiation | Reçu de mise signé, grand livre append-only chaîné par HMAC, journal d'audit | `ledger.py` |
| Double paiement | Transition d'état atomique `UPDATE ... WHERE status = ?` | `routes.py` |
| IDOR / fuite | Pari invisible (404) hors bookie/invités/admin, portefeuille lié au jeton | `routes.py` |
| Fuite d'informations | Erreurs JSON génériques, stacktraces uniquement côté serveur, en-tête `Server` neutre | `__init__.py`, `devserver.py` |
| Injection | Requêtes SQL paramétrées, validation stricte pydantic (`extra=forbid`) | partout |
| Déni de service | Rate limiting par IP, corps limité à 16 Ko, montants plafonnés | `__init__.py`, `config.py` |
| Secrets | Variables d'environnement, `.env` ignoré, refus de démarrer sans secret en production | `config.py` |

## Limites connues du MVP
- Rate limiting en mémoire : il ne fonctionne que sur une seule instance (Redis nécessaire en production).
- Verrouillage par nom d'utilisateur : un attaquant peut bloquer un compte pendant 60 s. Ajouter un CAPTCHA et une limite par IP.
- Collusion bookie + parieur : elle est atténuée par la contestation et l'arbitrage, mais pas éliminée. Il faut une détection de fraude.
- KYC (vérification d'identité) : il est délégué au prestataire de paiement et n'est pas simulé ici.
