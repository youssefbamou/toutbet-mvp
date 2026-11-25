"""Lancement local : `python -m toutbet` (serveur de développement, sans mode debug).

En production : `gunicorn "toutbet:create_app()"` derrière un reverse proxy TLS.
"""
import os

from . import create_app
from .devserver import make_dev_server

if __name__ == "__main__":
    app = create_app()
    host = os.environ.get("TOUTBET_HOST", "127.0.0.1")
    port = int(os.environ.get("TOUTBET_PORT", "5000"))
    print(f"ToutBet' sur http://{host}:{port}")
    make_dev_server(app, host, port).serve_forever()
