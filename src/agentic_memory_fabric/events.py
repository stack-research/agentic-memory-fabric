"""Core event types and validation helpers for AMF."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Mapping, Sequence
from uuid import UUID


VALID_EVENT_TYPES = frozenset(
    {
        "created",
        "updated",
        "superseded",
        "promoted",
        "linked",
        "reinforced",
        "conflicted",
        "recalled",
        "reconsolidated",
        "quarantined",
        "released",
        "expired",
        "deleted",
        "imported",
        "attested",
    }
)

VALID_TRUST_STATES = frozenset({"trusted", "quarantined", "expired"})
VALID_MEMORY_CLASSES = frozenset({"episodic", "semantic"})
DEFAULT_MEMORY_CLASS = "episodic"
VALID_ACTOR_KINDS = frozenset({"user", "service", "tool"})
VALID_EVIDENCE_TYPES = frozenset(
    {"url", "message_id", "file_path", "tool_run_id", "opaque"}
)
VALID_SIGNATURE_ALGS = frozenset({"hmac-sha256", "ed25519"})
VALID_ATTESTATION_TRUST_LEVELS = frozenset({"low", "medium", "high"})


def _is_json_value(value: Any) -> bool:
    if value is None or isinstance(value, (str, bool, int, float)):
        return True
    if isinstance(value, Mapping):
        return all(isinstance(key, str) and _is_json_value(item) for key, item in value.items())
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        return all(_is_json_value(item) for item in value)
    return False


def canonical_json_dumps(value: Any) -> str:
    if not _is_json_value(value):
        raise ValueError("payload must be JSON-serializable")
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def canonical_payload_hash(value: Any) -> str:
    digest = hashlib.sha256(canonical_json_dumps(value).encode("utf-8")).hexdigest()
    return f"sha256:{digest}"


def payload_to_retrieval_text(value: Any) -> str | None:
    if value is None:
        return None
    if isinstance(value, str):
        text = value.strip()
        return text or None
    text = canonical_json_dumps(value).strip()
    return text or None


def _as_uuid(value: str, *, field_name: str) -> str:
    try:
        UUID(value)
    except (ValueError, AttributeError) as exc:
        raise ValueError(f"{field_name} must be a valid UUID string") from exc
    return value


def _require_non_empty_string(value: Any, *, field_name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{field_name} must be a non-empty string")
    return value


def _validate_iso_datetime(value: str, *, field_name: str) -> str:
    try:
        datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError(f"{field_name} must be a valid ISO-8601 datetime") from exc
    return value


@dataclass(frozen=True)
class Actor:
    id: str
    kind: str
    display_name: str | None = None
    invocation_id: str | None = None

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "Actor":
        actor_id = _require_non_empty_string(data.get("id"), field_name="actor.id")
        kind = _require_non_empty_string(data.get("kind"), field_name="actor.kind")
        if kind not in VALID_ACTOR_KINDS:
            raise ValueError(f"actor.kind must be one of {sorted(VALID_ACTOR_KINDS)}")
        return cls(
            id=actor_id,
            kind=kind,
            display_name=data.get("display_name"),
            invocation_id=data.get("invocation_id"),
        )

    def to_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {"id": self.id, "kind": self.kind}
        if self.display_name is not None:
            out["display_name"] = self.display_name
        if self.invocation_id is not None:
            out["invocation_id"] = self.invocation_id
        return out


@dataclass(frozen=True)
class EvidenceRef:
    type: str
    ref: str
    digest: str | None = None

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "EvidenceRef":
        evidence_type = _require_non_empty_string(
            data.get("type"), field_name="evidence_refs[].type"
        )
        if evidence_type not in VALID_EVIDENCE_TYPES:
            raise ValueError(
                f"evidence_refs[].type must be one of {sorted(VALID_EVIDENCE_TYPES)}"
            )
        ref = _require_non_empty_string(data.get("ref"), field_name="evidence_refs[].ref")
        digest = data.get("digest")
        if digest is not None and not isinstance(digest, str):
            raise ValueError("evidence_refs[].digest must be a string when provided")
        return cls(type=evidence_type, ref=ref, digest=digest)

    def to_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {"type": self.type, "ref": self.ref}
        if self.digest is not None:
            out["digest"] = self.digest
        return out


@dataclass(frozen=True)
class TrustTransition:
    to: str
    from_state: str | None = None
    reason: str | None = None

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "TrustTransition":
        to_state = _require_non_empty_string(data.get("to"), field_name="trust_transition.to")
        if to_state not in VALID_TRUST_STATES:
            raise ValueError(
                f"trust_transition.to must be one of {sorted(VALID_TRUST_STATES)}"
            )
        from_state = data.get("from")
        if from_state is not None:
            if not isinstance(from_state, str) or from_state not in VALID_TRUST_STATES:
                raise ValueError(
                    f"trust_transition.from must be one of {sorted(VALID_TRUST_STATES)}"
                )
        reason = data.get("reason")
        if reason is not None and not isinstance(reason, str):
            raise ValueError("trust_transition.reason must be a string when provided")
        return cls(to=to_state, from_state=from_state, reason=reason)

    def to_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {"to": self.to}
        if self.from_state is not None:
            out["from"] = self.from_state
        if self.reason is not None:
            out["reason"] = self.reason
        return out


@dataclass(frozen=True)
class EventSignature:
    alg: str
    key_id: str
    sig: str

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "EventSignature":
        alg = _require_non_empty_string(data.get("alg"), field_name="signature.alg")
        if alg not in VALID_SIGNATURE_ALGS:
            raise ValueError(f"signature.alg must be one of {sorted(VALID_SIGNATURE_ALGS)}")
        key_id = _require_non_empty_string(data.get("key_id"), field_name="signature.key_id")
        sig = _require_non_empty_string(data.get("sig"), field_name="signature.sig")
        return cls(alg=alg, key_id=key_id, sig=sig)

    def to_dict(self) -> dict[str, Any]:
        return {"alg": self.alg, "key_id": self.key_id, "sig": self.sig}


@dataclass(frozen=True)
class Attestation:
    issuer: str
    issued_at: str
    trust_level: str
    claims: Mapping[str, Any] | None = None

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "Attestation":
        issuer = _require_non_empty_string(data.get("issuer"), field_name="attestation.issuer")
        issued_at = _validate_iso_datetime(
            _require_non_empty_string(data.get("issued_at"), field_name="attestation.issued_at"),
            field_name="attestation.issued_at",
        )
        trust_level = _require_non_empty_string(
            data.get("trust_level"), field_name="attestation.trust_level"
        )
        if trust_level not in VALID_ATTESTATION_TRUST_LEVELS:
            raise ValueError(
                "attestation.trust_level must be one of "
                f"{sorted(VALID_ATTESTATION_TRUST_LEVELS)}"
            )
        claims = data.get("claims")
        if claims is not None and not isinstance(claims, Mapping):
            raise ValueError("attestation.claims must be an object when provided")
        return cls(issuer=issuer, issued_at=issued_at, trust_level=trust_level, claims=claims)

    def to_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {
            "issuer": self.issuer,
            "issued_at": self.issued_at,
            "trust_level": self.trust_level,
        }
        if self.claims is not None:
            out["claims"] = dict(self.claims)
        return out


@dataclass(frozen=True)
class EventTimestamp:
    wall_time: str
    tick: int | None = None

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "EventTimestamp":
        wall_time = _validate_iso_datetime(
            _require_non_empty_string(data.get("wall_time"), field_name="timestamp.wall_time"),
            field_name="timestamp.wall_time",
        )
        tick = data.get("tick")
        if tick is not None and (not isinstance(tick, int) or tick < 0):
            raise ValueError("timestamp.tick must be a non-negative integer when provided")
        return cls(wall_time=wall_time, tick=tick)

    def to_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {"wall_time": self.wall_time}
        if self.tick is not None:
            out["tick"] = self.tick
        return out


@dataclass(frozen=True)
class EventEnvelope:
    event_id: str
    sequence: int
    timestamp: EventTimestamp
    actor: Actor
    tenant_id: str
    memory_id: str
    event_type: str
    memory_class: str | None = None
    previous_events: tuple[str, ...] = field(default_factory=tuple)
    payload_hash: str = ""
    payload: Any | None = None
    promoted_from_memory_ids: tuple[str, ...] = field(default_factory=tuple)
    promoted_from_event_ids: tuple[str, ...] = field(default_factory=tuple)
    target_memory_id: str | None = None
    edge_weight: float | None = None
    edge_reason: str | None = None
    evidence_refs: tuple[EvidenceRef, ...] = field(default_factory=tuple)
    trust_transition: TrustTransition | None = None
    signature: EventSignature | None = None
    attestation: Attestation | None = None

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "EventEnvelope":
        validate_event_envelope(data)
        timestamp = EventTimestamp.from_dict(data["timestamp"])
        actor = Actor.from_dict(data["actor"])
        evidence_refs = tuple(EvidenceRef.from_dict(item) for item in data.get("evidence_refs", []))
        trust_transition_data = data.get("trust_transition")
        trust_transition = (
            TrustTransition.from_dict(trust_transition_data)
            if trust_transition_data is not None
            else None
        )
        signature_data = data.get("signature")
        signature = EventSignature.from_dict(signature_data) if signature_data is not None else None
        attestation_data = data.get("attestation")
        attestation = Attestation.from_dict(attestation_data) if attestation_data is not None else None
        return cls(
            event_id=data["event_id"],
            sequence=data["sequence"],
            timestamp=timestamp,
            actor=actor,
            tenant_id=data["tenant_id"],
            memory_id=data["memory_id"],
            event_type=data["event_type"],
            memory_class=data.get("memory_class"),
            previous_events=tuple(data["previous_events"]),
            payload_hash=data["payload_hash"],
            payload=data.get("payload"),
            promoted_from_memory_ids=tuple(data.get("promoted_from_memory_ids", [])),
            promoted_from_event_ids=tuple(data.get("promoted_from_event_ids", [])),
            target_memory_id=data.get("target_memory_id"),
            edge_weight=data.get("edge_weight"),
            edge_reason=data.get("edge_reason"),
            evidence_refs=evidence_refs,
            trust_transition=trust_transition,
            signature=signature,
            attestation=attestation,
        )

    def to_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {
            "event_id": self.event_id,
            "sequence": self.sequence,
            "timestamp": self.timestamp.to_dict(),
            "actor": self.actor.to_dict(),
            "tenant_id": self.tenant_id,
            "memory_id": self.memory_id,
            "event_type": self.event_type,
            "memory_class": self.memory_class,
            "previous_events": list(self.previous_events),
            "payload_hash": self.payload_hash,
        }
        if self.memory_class is None:
            out.pop("memory_class")
        if self.payload is not None:
            out["payload"] = self.payload
        if self.promoted_from_memory_ids:
            out["promoted_from_memory_ids"] = list(self.promoted_from_memory_ids)
        if self.promoted_from_event_ids:
            out["promoted_from_event_ids"] = list(self.promoted_from_event_ids)
        if self.target_memory_id is not None:
            out["target_memory_id"] = self.target_memory_id
        if self.edge_weight is not None:
            out["edge_weight"] = self.edge_weight
        if self.edge_reason is not None:
            out["edge_reason"] = self.edge_reason
        if self.evidence_refs:
            out["evidence_refs"] = [ref.to_dict() for ref in self.evidence_refs]
        if self.trust_transition is not None:
            out["trust_transition"] = self.trust_transition.to_dict()
        if self.signature is not None:
            out["signature"] = self.signature.to_dict()
        if self.attestation is not None:
            out["attestation"] = self.attestation.to_dict()
        return out


def validate_event_envelope(data: Mapping[str, Any]) -> None:
    required_fields = {
        "event_id",
        "sequence",
        "timestamp",
        "actor",
        "tenant_id",
        "memory_id",
        "event_type",
        "previous_events",
        "payload_hash",
    }
    missing = sorted(required_fields - set(data.keys()))
    if missing:
        raise ValueError(f"Missing required fields: {', '.join(missing)}")

    _as_uuid(data["event_id"], field_name="event_id")
    _as_uuid(data["memory_id"], field_name="memory_id")

    sequence = data["sequence"]
    if not isinstance(sequence, int) or sequence < 1:
        raise ValueError("sequence must be an integer >= 1")

    if not isinstance(data["timestamp"], Mapping):
        raise ValueError("timestamp must be an object")
    EventTimestamp.from_dict(data["timestamp"])

    if not isinstance(data["actor"], Mapping):
        raise ValueError("actor must be an object")
    Actor.from_dict(data["actor"])
    _require_non_empty_string(data["tenant_id"], field_name="tenant_id")

    event_type = _require_non_empty_string(data["event_type"], field_name="event_type")
    if event_type not in VALID_EVENT_TYPES:
        raise ValueError(f"event_type must be one of {sorted(VALID_EVENT_TYPES)}")
    memory_class = data.get("memory_class")
    if memory_class is not None:
        memory_class = _require_non_empty_string(memory_class, field_name="memory_class")
        if memory_class not in VALID_MEMORY_CLASSES:
            raise ValueError(f"memory_class must be one of {sorted(VALID_MEMORY_CLASSES)}")

    previous_events = data["previous_events"]
    if not isinstance(previous_events, Sequence) or isinstance(previous_events, (str, bytes)):
        raise ValueError("previous_events must be an array")
    dedupe_check: set[str] = set()
    for prev_event_id in previous_events:
        _as_uuid(prev_event_id, field_name="previous_events[]")
        if prev_event_id in dedupe_check:
            raise ValueError("previous_events must not contain duplicates")
        dedupe_check.add(prev_event_id)

    payload_hash = _require_non_empty_string(data["payload_hash"], field_name="payload_hash")
    if not payload_hash.startswith("sha256:") or len(payload_hash) != len("sha256:") + 64:
        raise ValueError("payload_hash must match sha256:<64_hex_chars>")
    hash_body = payload_hash.split("sha256:", 1)[1]
    if not all(ch in "0123456789abcdefABCDEF" for ch in hash_body):
        raise ValueError("payload_hash must match sha256:<64_hex_chars>")
    payload = data.get("payload")
    if payload is not None:
        expected_hash = canonical_payload_hash(payload)
        if expected_hash != payload_hash:
            raise ValueError("payload_hash must match the canonical hash of payload when payload is provided")

    promoted_from_memory_ids = data.get("promoted_from_memory_ids")
    if promoted_from_memory_ids is not None:
        if not isinstance(promoted_from_memory_ids, Sequence) or isinstance(
            promoted_from_memory_ids, (str, bytes)
        ):
            raise ValueError("promoted_from_memory_ids must be an array when provided")
        for item in promoted_from_memory_ids:
            _as_uuid(item, field_name="promoted_from_memory_ids[]")

    promoted_from_event_ids = data.get("promoted_from_event_ids")
    if promoted_from_event_ids is not None:
        if not isinstance(promoted_from_event_ids, Sequence) or isinstance(
            promoted_from_event_ids, (str, bytes)
        ):
            raise ValueError("promoted_from_event_ids must be an array when provided")
        for item in promoted_from_event_ids:
            _as_uuid(item, field_name="promoted_from_event_ids[]")

    target_memory_id = data.get("target_memory_id")
    if target_memory_id is not None:
        _as_uuid(target_memory_id, field_name="target_memory_id")

    edge_weight = data.get("edge_weight")
    if edge_weight is not None:
        if not isinstance(edge_weight, (int, float)):
            raise ValueError("edge_weight must be a number when provided")
        if float(edge_weight) < 0:
            raise ValueError("edge_weight must be >= 0 when provided")

    edge_reason = data.get("edge_reason")
    if edge_reason is not None:
        _require_non_empty_string(edge_reason, field_name="edge_reason")

    evidence_refs = data.get("evidence_refs")
    if evidence_refs is not None:
        if not isinstance(evidence_refs, Sequence) or isinstance(evidence_refs, (str, bytes)):
            raise ValueError("evidence_refs must be an array when provided")
        for item in evidence_refs:
            if not isinstance(item, Mapping):
                raise ValueError("evidence_refs[] must be an object")
            EvidenceRef.from_dict(item)

    trust_transition = data.get("trust_transition")
    if trust_transition is not None:
        if not isinstance(trust_transition, Mapping):
            raise ValueError("trust_transition must be an object when provided")
        TrustTransition.from_dict(trust_transition)

    signature = data.get("signature")
    if signature is not None:
        if not isinstance(signature, Mapping):
            raise ValueError("signature must be an object when provided")
        EventSignature.from_dict(signature)

    attestation = data.get("attestation")
    if attestation is not None:
        if not isinstance(attestation, Mapping):
            raise ValueError("attestation must be an object when provided")
        Attestation.from_dict(attestation)

    if event_type == "imported":
        if evidence_refs is None or len(evidence_refs) == 0:
            raise ValueError("imported events must include at least one evidence_ref")
    if event_type == "promoted":
        if memory_class != "semantic":
            raise ValueError("promoted events must set memory_class to semantic")
        if payload is None:
            raise ValueError("promoted events must include payload")
        if not promoted_from_memory_ids or not promoted_from_event_ids:
            raise ValueError(
                "promoted events must include promoted_from_memory_ids and promoted_from_event_ids"
            )
        if len(promoted_from_memory_ids) != len(promoted_from_event_ids):
            raise ValueError(
                "promoted_from_memory_ids and promoted_from_event_ids must have the same length"
            )
        if list(previous_events) != list(promoted_from_event_ids):
            raise ValueError(
                "promoted events must use promoted_from_event_ids as previous_events"
            )
    if event_type == "linked":
        if target_memory_id is None:
            raise ValueError("linked events must include target_memory_id")
    if event_type == "conflicted":
        if target_memory_id is None:
            raise ValueError("conflicted events must include target_memory_id")
    if event_type == "reinforced" and target_memory_id is None and edge_reason is None:
        # Keep the event small but still attributable when reinforcing without an edge.
        pass
