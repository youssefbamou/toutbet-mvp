"""Serveur HTTP de développement sans divulgation de versions.

Par défaut, Werkzeug répond `Server: Werkzeug/3.x Python/3.x` : un attaquant connaît
alors les versions exactes à cibler (défaut relevé par notre scan DAST).
En production, utiliser gunicorn derrière un reverse proxy qui réécrit cet en-tête.
"""
from werkzeug.serving import WSGIRequestHandler, make_server


class _QuietHandler(WSGIRequestHandler):
    def version_string(self):
        return "ToutBet"


def make_dev_server(app, host: str, port: int):
    return make_server(host, port, app, threaded=True, request_handler=_QuietHandler)
