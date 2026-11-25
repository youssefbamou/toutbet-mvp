# Rapport DAST / IAST / Fuzzing — ToutBet'

Date : 2026-11-24 14:33 — graine 42, 500 itérations

| Type | Test | Résultat | Détail |
|---|---|---|---|
| DAST | En-tête Strict-Transport-Security présent | OK | max-age=63072000; includeSubDomains |
| DAST | En-tête Content-Security-Policy présent | OK | default-src 'none'; frame-ancestors 'none' |
| DAST | En-tête X-Content-Type-Options présent | OK | nosniff |
| DAST | En-tête X-Frame-Options présent | OK | DENY |
| DAST | En-tête Referrer-Policy présent | OK | no-referrer |
| DAST | En-tête Cache-Control présent | OK | no-store |
| DAST | En-tête Server ne révèle pas de version précise | OK | ToutBet |
| DAST | CORS : origine tierce non autorisée | OK | aucun ACAO |
| DAST | Méthode TRACE refusée | OK | 405 |
| DAST | GET /wallet sans jeton -> 401 | OK | 401 |
| DAST | GET /bets sans jeton -> 401 | OK | 401 |
| DAST | POST /bets sans jeton -> 401 | OK | 401 |
| DAST | POST /wallet/withdraw sans jeton -> 401 | OK | 401 |
| DAST | POST /bets/1/settle sans jeton -> 401 | OK | 401 |
| DAST | POST /bets/1/cancel sans jeton -> 401 | OK | 401 |
| DAST | Jeton forgé '' rejeté | OK | 401 |
| DAST | Jeton forgé 'null' rejeté | OK | 401 |
| DAST | Jeton forgé "' OR 1=1 --" rejeté | OK | 401 |
| DAST | Jeton forgé 'AAAAAAAAAAAAAAAAAAAA' rejeté | OK | 401 |
| DAST | Jeton forgé '../../etc/passwdxxxx' rejeté | OK | 401 |
| DAST | IDOR : énumération des paris d'autrui impossible | OK | {404: 20} |
| DAST | IDOR : mise sur pari non invité refusée | OK | 404 |
| DAST | Élévation : annulation réservée à l'admin | OK | 403 |
| DAST | Webhook paiement non signé refusé | OK | 401 |
| DAST | 404 générique sans fuite | OK | {"error":"not_found"}  |
| DAST | JSON invalide : erreur générique | OK | {"error":"invalid_json"}  |
| DAST | Corps > 16 Ko refusé (413) | OK | 413 |
| Fuzzing | 500 entrées aléatoires sur POST /bets : aucune erreur 500 | OK | codes={422: 437, 404: 49, 400: 53, 201: 10, 200: 1} ; crashs=[] |
| Fuzzing | Aucune réponse ne révèle la structure interne | OK | [] |
| IAST | 610 requêtes SQL tracées : aucune charge utile interprétée comme du SQL | OK | [] |
| IAST | Aucune exception non gérée côté serveur | OK | [] |
| IAST | Pas de requête HTTP déclenchant un nombre anormal de requêtes SQL (N+1 / DoS) | OK | max=[('1cb3083db9398983', 7)] |

**32/32 tests réussis.**
