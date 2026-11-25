"""Lancement : `python -m toutbet`.

Utilise waitress (serveur WSGI de production, compatible Windows et Linux) s'il est installé :
connexions keep-alive, pool de threads, en-tête `Server` neutre.
Sinon, repli sur le serveur de développement (une connexion TCP par requête : à éviter en charge).

Constat du test de charge Locust (atelier 2) : avec le serveur de développement, chaque requête
ouvre une nouvelle connexion ; sous 500 utilisateurs, Windows épuise ses ports (WinError 10048).
"""
import os

from . import create_app
from .devserver import make_dev_server

if __name__ == "__main__":
    app = create_app()
    host = os.environ.get("TOUTBET_HOST", "127.0.0.1")
    port = int(os.environ.get("TOUTBET_PORT", "5000"))
    try:
        from waitress import serve
    except ImportError:
        print(f"ToutBet' sur http://{host}:{port} (serveur de développement : installer waitress pour la charge)")
        make_dev_server(app, host, port).serve_forever()
    else:
        threads = int(os.environ.get("TOUTBET_THREADS", "16"))
        print(f"ToutBet' sur http://{host}:{port} (waitress, {threads} threads)")
        serve(app, host=host, port=port, threads=threads, ident="ToutBet", connection_limit=2000)
