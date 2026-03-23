"""Deterministic event signing and verification utilities."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import subprocess
import tempfile
from dataclasses import dataclass
from typing import Any, Callable, Mapping

from .events import EventEnvelope

SignatureState = str  # "verified" | "unsigned" | "invalid" | "key_missing" | "revoked"

KEY_STATUS_ACTIVE = "active"
KEY_STATUS_REVOKED = "revoked"
SUPPORTED_KEY_STATUSES = frozenset({KEY_STATUS_ACTIVE, KEY_STATUS_REVOKED})


@dataclass(frozen=True)
class KeyMaterial:
    key: bytes | str | Mapping[str, Any]
    status: str = KEY_STATUS_ACTIVE


KeyResolver = Callable[[str], bytes | str | Mapping[str, Any] | KeyMaterial | None]

SUPPORTED_SIGNATURE_ALGS = frozenset({"hmac-sha256", "ed25519"})


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


def _to_key_bytes(key: bytes | str) -> bytes:
    return key.encode("utf-8") if isinstance(key, str) else key


def _decode_base64_any(value: str) -> bytes:
    padded = value + ("=" * (-len(value) % 4))
    # Use a single decoder that supports both standard base64 and base64url
    # (where '+'/' are replaced by '-'/'_'). This avoids intermittent decode
    # failures depending on the alphabet used in the input string.
    return base64.b64decode(padded.encode("ascii"), altchars=b"-_")


def _ed25519_public_key_bytes_from_material(material: bytes | str | Mapping[str, Any]) -> bytes | None:
    if isinstance(material, bytes):
        return material if len(material) == 32 else None
    if isinstance(material, str):
        text = material.strip()
        if not text:
            return None
        if text.startswith("ed25519:"):
            text = text.split(":", 1)[1]
        try:
            decoded = _decode_base64_any(text)
        except Exception:
            return None
        return decoded if len(decoded) == 32 else None
    if isinstance(material, Mapping):
        kty = str(material.get("kty", "")).strip()
        crv = str(material.get("crv", "")).strip()
        x = material.get("x")
        if kty != "OKP" or crv != "Ed25519" or not isinstance(x, str):
            return None
        try:
            decoded = _decode_base64_any(x)
        except Exception:
            return None
        return decoded if len(decoded) == 32 else None
    return None


def _verify_ed25519_signature(
    *,
    message: bytes,
    signature: bytes,
    public_key_bytes: bytes,
) -> bool:
    # RFC 8410 SubjectPublicKeyInfo prefix for Ed25519 public keys.
    spki_prefix = bytes.fromhex("302a300506032b6570032100")
    pub_der = spki_prefix + public_key_bytes
    # Keep PEM line breaks intact; some OpenSSL builds are stricter than others.
    pub_b64 = base64.encodebytes(pub_der).decode("ascii")
    pub_pem = "-----BEGIN PUBLIC KEY-----\n" + pub_b64 + "-----END PUBLIC KEY-----\n"
    with tempfile.TemporaryDirectory() as tmpdir:
        msg_path = f"{tmpdir}/msg.bin"
        sig_path = f"{tmpdir}/sig.bin"
        pub_path = f"{tmpdir}/pub.pem"
        with open(msg_path, "wb") as msg_file:
            msg_file.write(message)
        with open(sig_path, "wb") as sig_file:
            sig_file.write(signature)
        with open(pub_path, "w", encoding="ascii") as pub_file:
            pub_file.write(pub_pem)
        result = subprocess.run(
            [
                "openssl",
                "pkeyutl",
                "-verify",
                "-pubin",
                "-inkey",
                pub_path,
                "-rawin",
                "-in",
                msg_path,
                "-sigfile",
                sig_path,
            ],
            check=False,
            capture_output=True,
            text=False,
        )
    return result.returncode == 0


def _resolve_key_for_verify(
    key_resolver: KeyResolver,
    key_id: str,
) -> tuple[bytes | str | Mapping[str, Any] | None, SignatureState]:
    resolved = key_resolver(key_id)
    if resolved is None:
        return None, "key_missing"
    if isinstance(resolved, KeyMaterial):
        if resolved.status not in SUPPORTED_KEY_STATUSES:
            return None, "invalid"
        if resolved.status == KEY_STATUS_REVOKED:
            return None, "revoked"
        return resolved.key, "verified"
    return resolved, "verified"


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

    key_bytes, key_status = _resolve_key_for_verify(key_resolver, event.signature.key_id)
    if key_status != "verified" or key_bytes is None:
        return key_status

    if event.signature.alg == "hmac-sha256":
        if not isinstance(key_bytes, (bytes, str)):
            return "invalid"
        expected_sig = sign_event(event, key_id=event.signature.key_id, key=key_bytes)
        if hmac.compare_digest(expected_sig, event.signature.sig):
            return "verified"
        return "invalid"

    if event.signature.alg == "ed25519":
        public_key_bytes = _ed25519_public_key_bytes_from_material(key_bytes)
        if public_key_bytes is None:
            return "invalid"
        try:
            signature_bytes = _decode_base64_any(event.signature.sig)
        except Exception:
            return "invalid"
        if len(signature_bytes) != 64:
            return "invalid"
        is_valid = _verify_ed25519_signature(
            message=canonicalize_event_for_signing(event),
            signature=signature_bytes,
            public_key_bytes=public_key_bytes,
        )
        return "verified" if is_valid else "invalid"

    return "invalid"
