"""Mode IAST « maison » : instrumentation interne de l'application.

Quand TOUTBET_IAST_TRACE=1, chaque requête SQL exécutée est journalisée avec
l'identifiant de la requête HTTP qui l'a déclenchée. Le script DAST
(`security/dast_fuzz.py`) corrèle ensuite ses entrées malveillantes avec le SQL
réellement exécuté : si une charge utile apparaît DANS le texte SQL (et non comme
paramètre), c'est une injection. Interdit en production (voir config.py).
"""
import logging

from flask import g, has_request_context

trace_log = logging.getLogger("toutbet.iast")


def attach_sql_tracer(conn):
    def _trace(statement: str):
        rid = g.get("request_id", "-") if has_request_context() else "-"
        trace_log.info("sql request_id=%s stmt=%s", rid, statement.replace("\n", " ")[:500])

    conn.set_trace_callback(_trace)
