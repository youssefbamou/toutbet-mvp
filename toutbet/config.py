"""Configuration de ToutBet'.

Aucun secret n'est écrit dans le code : ils viennent des variables d'environnement.
En production, l'application refuse de démarrer si un secret manque.
"""
import os
import secrets


class ConfigError(RuntimeError):
    pass


def _env_int(name: str, default: int) -> int:
    raw = os.environ.get(name)
    if raw is None or raw == "":
        return default
    return int(raw)


def load_config(overrides: dict | None = None) -> dict:
    env = os.environ.get("TOUTBET_ENV", "development")
    cfg = {
        "ENV": env,
        "DATABASE": os.environ.get("TOUTBET_DATABASE", "toutbet.sqlite3"),
        "SECRET_KEY": os.environ.get("TOUTBET_SECRET_KEY"),
        "PAYMENT_WEBHOOK_SECRET": os.environ.get("TOUTBET_PAYMENT_WEBHOOK_SECRET"),
        # Commission plateforme en points de base (500 = 5 %)
        "PLATFORM_FEE_BP": _env_int("TOUTBET_PLATFORM_FEE_BP", 500),
        # Commission bookie maximale autorisée (1000 = 10 %)
        "MAX_BOOKIE_FEE_BP": _env_int("TOUTBET_MAX_BOOKIE_FEE_BP", 1000),
        # Délai de contestation après la proposition d'un résultat (secondes)
        "DISPUTE_WINDOW_SECONDS": _env_int("TOUTBET_DISPUTE_WINDOW_SECONDS", 3600),
        "TOKEN_TTL_SECONDS": _env_int("TOUTBET_TOKEN_TTL_SECONDS", 3600),
        "RATE_LIMIT_PER_MINUTE": _env_int("TOUTBET_RATE_LIMIT_PER_MINUTE", 120),
        "LOGIN_MAX_FAILURES": _env_int("TOUTBET_LOGIN_MAX_FAILURES", 5),
        "MAX_STAKE_CENTS": _env_int("TOUTBET_MAX_STAKE_CENTS", 100_000),  # 1 000 €
        "MAX_DEPOSIT_CENTS": _env_int("TOUTBET_MAX_DEPOSIT_CENTS", 100_000),
        # Trace SQL par requête (mode IAST maison) — jamais en production
        "IAST_TRACE": os.environ.get("TOUTBET_IAST_TRACE") == "1",
        "MAX_CONTENT_LENGTH": 16 * 1024,
    }
    if overrides:
        cfg.update(overrides)

    for key in ("SECRET_KEY", "PAYMENT_WEBHOOK_SECRET"):
        if not cfg.get(key):
            if cfg["ENV"] == "production":
                raise ConfigError(f"Variable d'environnement manquante pour {key}")
            # Développement / tests : secret éphémère, jamais persisté
            cfg[key] = secrets.token_hex(32)
    if cfg["ENV"] == "production" and cfg["IAST_TRACE"]:
        raise ConfigError("IAST_TRACE interdit en production")
    return cfg
