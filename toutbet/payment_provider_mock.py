"""Simulacre (mock) du prestataire de paiement, pour les tests et la démo.

En réalité, c'est le prestataire (Stripe, Mangopay...) qui signe ses notifications
avec un secret partagé. Ici, on reproduit ce comportement pour tester la vérification
de signature et l'idempotence sans appeler de service externe.
"""
import hashlib
import hmac
import json
import secrets


def signed_deposit(webhook_secret: str, username: str, amount_cents: int, event_id: str | None = None):
    body = json.dumps({
        "event_id": event_id or "evt_" + secrets.token_hex(8),
        "type": "payment.succeeded",
        "username": username,
        "amount_cents": amount_cents,
    }).encode()
    sig = hmac.new(webhook_secret.encode(), body, hashlib.sha256).hexdigest()
    return body, {"Content-Type": "application/json", "X-Signature": sig}
