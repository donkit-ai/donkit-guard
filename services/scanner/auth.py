from __future__ import annotations

import base64
import hashlib
import hmac
import time
from typing import TYPE_CHECKING

import httpx
from fastapi import HTTPException, Request
from pydantic import ValidationError

from donkit_guard.scanning.models import Actor, Contract

from .config import Configuration, configuration

if TYPE_CHECKING:
    from .store import Store


class Membership(Contract):
    active: bool


async def active(actor: Actor, config: Configuration) -> bool:
    if actor.issuer == "standalone":
        return any(t.actor == actor for t in config.tokens)
    if actor.issuer != "donkit" or not config.membership_url:
        return False
    try:
        async with httpx.AsyncClient(timeout=5, follow_redirects=False, trust_env=False) as client:
            response = await client.post(
                config.membership_url,
                content=actor.model_dump_json(),
                headers={
                    "Authorization": f"Bearer {config.host_secret.get_secret_value()}",
                    "Content-Type": "application/json",
                },
            )
            response.raise_for_status()
            return Membership.model_validate_json(response.content).active
    except (httpx.HTTPError, ValidationError):
        # Failure to prove current membership denies execution, including network outages.
        return False


async def identity(request: Request) -> Actor:
    config = configuration()
    authorization = request.headers.get("authorization", "")
    if authorization.startswith("Bearer "):
        digest = hashlib.sha256(authorization[7:].encode()).hexdigest()
        for token in config.tokens:
            if hmac.compare_digest(digest, token.sha256):
                return token.actor
        raise HTTPException(401, "Invalid scanner token")
    secret = config.host_secret.get_secret_value()
    encoded = request.headers.get("x-guard-actor", "")
    timestamp = request.headers.get("x-guard-time", "")
    nonce = request.headers.get("x-guard-nonce", "")
    signature = request.headers.get("x-guard-signature", "")
    try:
        recent = abs(time.time() - int(timestamp)) <= 60
    except ValueError:
        recent = False
    if not secret or not recent or len(nonce) != 32 or len(encoded) > 2048:
        raise HTTPException(401, "Invalid host identity")
    body_digest = hashlib.sha256(await request.body()).hexdigest()
    message = "\n".join((request.method, request.url.path, body_digest, timestamp, nonce, encoded))
    expected = hmac.new(secret.encode(), message.encode(), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected, signature):
        raise HTTPException(401, "Invalid host signature")
    try:
        actor = Actor.model_validate_json(base64.urlsafe_b64decode(encoded))
    except (ValueError, ValidationError) as exc:
        raise HTTPException(401, "Invalid host identity") from exc
    store: Store = request.app.state.store
    if actor.issuer != "donkit" or not store.consume_nonce(nonce):
        raise HTTPException(401, "Invalid or replayed host request")
    if not await active(actor, config):
        raise HTTPException(403, "Active employee membership required")
    return actor
