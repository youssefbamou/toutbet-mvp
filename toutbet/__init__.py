"""ToutBet' — API du MVP de paris personnalisés entre particuliers."""
import logging
import secrets

import click
from flask import Flask, g, jsonify, request
from werkzeug.exceptions import HTTPException

from .config import load_config
from .db import close_db, connect, init_db, now
from .routes import ApiError, bp
from .security import SECURITY_HEADERS, client_ip, hash_password, limiter

log = logging.getLogger("toutbet")


def create_app(overrides: dict | None = None) -> Flask:
    app = Flask(__name__)
    app.config.update(load_config(overrides))
    app.config["PROPAGATE_EXCEPTIONS"] = False
    app.json.sort_keys = False

    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
    init_db(app.config["DATABASE"])
    app.register_blueprint(bp)
    app.teardown_appcontext(close_db)

    @app.before_request
    def _before():
        g.request_id = secrets.token_hex(8)
        if not limiter.hit(f"ip:{client_ip()}", app.config["RATE_LIMIT_PER_MINUTE"]):
            log.warning("rate_limited ip=%s path=%s", client_ip(), request.path)
            return jsonify({"error": "rate_limited"}), 429

    @app.after_request
    def _after(resp):
        resp.headers.update(SECURITY_HEADERS)
        resp.headers["X-Request-Id"] = g.get("request_id", "-")
        return resp

    @app.errorhandler(ApiError)
    def _api_error(e: ApiError):
        return jsonify({"error": e.code}), e.status

    @app.errorhandler(HTTPException)
    def _http_error(e: HTTPException):
        # Réponse JSON générique : pas de page HTML Werkzeug, pas de détail interne
        return jsonify({"error": e.name.lower().replace(" ", "_")}), e.code

    @app.errorhandler(Exception)
    def _unhandled(e: Exception):
        # La stacktrace reste dans les logs serveur ; le client ne reçoit qu'un identifiant
        log.exception("unhandled_error request_id=%s path=%s", g.get("request_id"), request.path)
        return jsonify({"error": "internal_error", "request_id": g.get("request_id")}), 500

    @app.cli.command("create-admin")
    @click.argument("username")
    def create_admin(username):
        """Crée un administrateur (arbitre des litiges). Le mot de passe est demandé, jamais passé en argument."""
        password = click.prompt("Mot de passe", hide_input=True, confirmation_prompt=True)
        if len(password) < 12:
            raise click.ClickException("12 caractères minimum")
        conn = connect(app.config["DATABASE"])
        try:
            conn.execute(
                "INSERT INTO users (username, password_hash, role, created_at) VALUES (?, ?, 'admin', ?)",
                (username, hash_password(password), now()),
            )
        finally:
            conn.close()
        click.echo("Administrateur créé.")

    return app
