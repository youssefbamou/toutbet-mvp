# Analyse statique locale (ruff + règles Bandit « S ») — avant / après

Commande : `ruff check --select E,F,W,B,S .`

## Avant correction : 51 alertes
| Nb | Fichier | Règle | Signification |
|---|---|---|---|
| 19 | security/dast_fuzz.py | S113 | Appel `requests` sans timeout (blocage possible) |
| 11 | tests/test_concurrency.py | S113 | Appel `requests` sans timeout |
| 6 | toutbet/routes.py | B904 | `raise` dans un `except` sans `from` : chaînage de l'exception interne |
| 1 | toutbet/settlement.py | S101 | `assert` de sécurité (désactivé avec `python -O`) |
| 2+1+1 | dast_fuzz / tests | E741, F841 | Variable ambiguë `l`, variable inutilisée |
| 5 | tests, load, security | S105 | « Mot de passe en dur » : mots de passe de test fictifs |
| 4 | tests, load, security | S311 | `random` non cryptographique |
| 1 | security/dast_fuzz.py | E402 | Import après `sys.path.insert` |

## Corrections
- S113 : `timeout=10` ajouté sur tous les appels réseau.
- B904 : `raise ApiError(...) from None` : l'exception interne n'est pas chaînée vers la réponse.
- S101 : l'`assert` d'invariant financier est remplacé par un contrôle explicite qui lève une erreur (fail-safe).
- E741 / F841 : code nettoyé.

## Alertes justifiées (faux positifs, ignorées par fichier dans `ruff.toml`)
- S105 : mots de passe fictifs utilisés uniquement dans les tests et les scripts de charge.
- S311 : `random` sert au fuzzing et à la simulation de charge, pas à la cryptographie. Les jetons utilisent `secrets`.
- E402 : import volontaire après ajustement du chemin dans les scripts autonomes.

## Après correction : 0 alerte (`All checks passed!`)
