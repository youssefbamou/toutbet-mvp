# Prompts utilisés pour générer le socle technique

**Modèle :** Claude Opus 5.5 (Anthropic), utilisé en mode agent : le modèle écrit le code, l'exécute et lance
les tests dans son environnement.
**Recommandations du cours appliquées :** le prompt est une spécification précise et historisée en markdown
(auditabilité). Il impose les mitigations STRIDE pour limiter les « dérives créatives ». Le code produit fait
ensuite l'objet d'une revue humaine et de scans SAST et DAST, car valider n'est pas coder.

---

## Prompt 1 — Génération du socle (atelier 1, étape 4)

```text
Rôle : tu es un développeur backend senior spécialisé en sécurité applicative (DevSecOps).

Contexte : ToutBet' est une plateforme mobile-first de paris personnalisés entre particuliers.
Un Bookie crée un pari (question oui/non), fixe éventuellement une mise minimum et invite des Parieurs.
L'argent est séquestré par la plateforme puis redistribué aux gagnants après validation du résultat,
après prélèvement de la commission du bookie et de celle de la plateforme.

Tâche : génère le socle d'une API REST en Python 3.12 (Flask, SQLite, pydantic), sans dépendance
superflue, couvrant ce backlog MVP : inscription/connexion ; dépôt via webhook du prestataire de
paiement ; retrait ; création de pari ; invitations ; mise ; proposition du résultat par le bookie ;
contestation par un parieur ; redistribution ; annulation par un administrateur arbitre.

Exigences de sécurité OBLIGATOIRES, issues de notre modélisation STRIDE :
- Spoofing : mots de passe hachés (scrypt), jetons aléatoires stockés hachés avec expiration,
  verrouillage après 5 échecs de connexion, message d'erreur identique que le compte existe ou non ;
  webhook de paiement signé HMAC-SHA256 vérifié à temps constant et idempotent (event_id).
- Tampering : montants en centimes entiers stricts > 0 et plafonnés ; aucune route de modification
  d'une mise ; mises et grand livre immuables en base (triggers) ; contrainte CHECK solde >= 0 ;
  le bookie ne peut pas miser sur son pari ; résultat proposé uniquement par le bookie et après clôture.
- Repudiation : reçu de mise signé (HMAC) renvoyé au parieur ; grand livre append-only chaîné par HMAC ;
  journal d'audit de toutes les actions financières.
- Information disclosure : erreurs JSON génériques, aucune stacktrace côté client ; un pari privé
  renvoie 404 à un non-invité ; requêtes SQL toujours paramétrées ; en-têtes HSTS, CSP, nosniff,
  X-Frame-Options.
- Denial of service : rate limiting par IP ; taille de corps limitée ; validation stricte (champs
  inconnus refusés).
- Elevation of privilege : rôle admin jamais modifiable via l'API ; contrôle du rôle côté serveur.
- Concurrence : toute écriture de solde passe par UNE fonction register_transaction, dans une
  transaction BEGIN IMMEDIATE, avec un débit conditionnel atomique
  (UPDATE ... WHERE balance >= montant) : impossible de dépenser plus que son solde,
  même avec des requêtes simultanées. Redistribution protégée contre le double paiement.
- Secrets : uniquement en variables d'environnement, jamais dans le code ; refus de démarrer en
  production si un secret manque ; fournir un .env.example et un .gitignore.

Livrables : le code, des tests pytest qui jouent chaque abuse story comme un attaquant,
un README. N'utilise aucune fonction obsolète. N'active jamais le mode debug.
```

## Prompt 2 — Tests offensifs (atelier 2)

```text
À partir du prototype ToutBet', écris :
1. un test où le même utilisateur lance de nombreux paris simultanés via un vrai serveur HTTP
   multithread, avec une démonstration du risque sur une implémentation naïve « check-then-act » ;
2. un script qui démarre l'API instrumentée et enchaîne des tests DAST (en-têtes, CORS, méthodes,
   authentification, IDOR, fuites dans les erreurs), du fuzzing (500 entrées aléatoires ou malformées
   sur POST /bets et sur les identifiants de chemin) et une analyse IAST (corrélation de chaque
   requête HTTP avec le SQL réellement exécuté, pour détecter une injection ou une exception non gérée) ;
   le script produit un rapport markdown ;
3. un locustfile simulant l'afflux de centaines de parieurs sur un même événement.
Corrige le code pour chaque défaut trouvé et ajoute un test de non-régression.
```

## Itérations après génération (revue et correction)

| Itération | Constat | Correction |
|---|---|---|
| 1 | Un test échouait : le jeton expirait pendant un scénario de contestation trop long. | Scénario de test corrigé (le code était correct). |
| 2 | Fuzzing : `GET /bets/1000000000000000000000000000000` provoquait une erreur 500 (`OverflowError`). | Identifiants bornés dans les routes ; tests de non-régression ajoutés. |
| 3 | DAST : l'en-tête `Server: Werkzeug/3.1.9 Python/3.13.18` exposait les versions. | En-tête neutralisé (`toutbet/devserver.py`). |
| 4 | Analyse statique (ruff, règles Bandit) : 51 alertes. | Timeouts réseau, `raise ... from None`, `assert` remplacé par un contrôle explicite ; faux positifs justifiés dans `ruff.toml`. |
