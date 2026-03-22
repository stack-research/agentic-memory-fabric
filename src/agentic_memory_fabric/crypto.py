"""Deterministic event signing and verification utilities."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
from typing import Callable

from .events import EventEnvelope

SignatureState = str  # "verified" | "unsigned" | "invalid"
KeyResolver = Callable[[str], bytes | str | None]

SUPPORTED_SIGNATURE_ALGS = frozenset({"hmac-sha256"})


def canonicalize_event_for_signing(event: EventEnvelope) -> bytes:
    """Return deterministic signing bytes with signature field excluded."""
    event_dict = event.to_dict()
    event_dict.pop("signature", None)
    canonical_json = json.dumps(
        event_dict,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    )
    return canonical_json.encode("utf-8")


def _resolve_key_bytes(key_resolver: KeyResolver, key_id: str) -> bytes | None:
    key = key_resolver(key_id)
    if key is None:
        return None
    if isinstance(key, str):
        return key.encode("utf-8")
    return key


def sign_event(event: EventEnvelope, *, key_id: str, key: bytes | str) -> str:
    """Create a base64 HMAC-SHA256 signature for the canonicalized event."""
    key_bytes = key.encode("utf-8") if isinstance(key, str) else key
    digest = hmac.new(key_bytes, canonicalize_event_for_signing(event), hashlib.sha256).digest()
    return base64.b64encode(digest).decode("ascii")


def verify_event_signature(
    event: EventEnvelope,
    *,
    key_resolver: KeyResolver,
) -> SignatureState:
    if event.signature is None:
        return "unsigned"

    if event.signature.alg not in SUPPORTED_SIGNATURE_ALGS:
        return "invalid"

    key_bytes = _resolve_key_bytes(key_resolver, event.signature.key_id)
    if key_bytes is None:
        return "invalid"

    expected_sig = sign_event(event, key_id=event.signature.key_id, key=key_bytes)
    if hmac.compare_digest(expected_sig, event.signature.sig):
        return "verified"
    return "invalid"
