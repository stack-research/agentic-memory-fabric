"""Core event types and validation helpers for AMF."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Mapping, Sequence
from uuid import UUID


VALID_EVENT_TYPES = frozenset(
    {
        "created",
        "updated",
        "superseded",
        "quarantined",
        "released",
        "expired",
        "deleted",
        "imported",
        "attested",
    }
)

VALID_TRUST_STATES = frozenset({"trusted", "quarantined", "expired"})
VALID_ACTOR_KINDS = frozenset({"user", "service", "tool"})
VALID_EVIDENCE_TYPES = frozenset(
    {"url", "message_id", "file_path", "tool_run_id", "opaque"}
)


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
    memory_id: str
    event_type: str
    previous_events: tuple[str, ...] = field(default_factory=tuple)
    payload_hash: str = ""
    evidence_refs: tuple[EvidenceRef, ...] = field(default_factory=tuple)
    trust_transition: TrustTransition | None = None

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
        return cls(
            event_id=data["event_id"],
            sequence=data["sequence"],
            timestamp=timestamp,
            actor=actor,
            memory_id=data["memory_id"],
            event_type=data["event_type"],
            previous_events=tuple(data["previous_events"]),
            payload_hash=data["payload_hash"],
            evidence_refs=evidence_refs,
            trust_transition=trust_transition,
        )

    def to_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {
            "event_id": self.event_id,
            "sequence": self.sequence,
            "timestamp": self.timestamp.to_dict(),
            "actor": self.actor.to_dict(),
            "memory_id": self.memory_id,
            "event_type": self.event_type,
            "previous_events": list(self.previous_events),
            "payload_hash": self.payload_hash,
        }
        if self.evidence_refs:
            out["evidence_refs"] = [ref.to_dict() for ref in self.evidence_refs]
        if self.trust_transition is not None:
            out["trust_transition"] = self.trust_transition.to_dict()
        return out


def validate_event_envelope(data: Mapping[str, Any]) -> None:
    required_fields = {
        "event_id",
        "sequence",
        "timestamp",
        "actor",
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

    event_type = _require_non_empty_string(data["event_type"], field_name="event_type")
    if event_type not in VALID_EVENT_TYPES:
        raise ValueError(f"event_type must be one of {sorted(VALID_EVENT_TYPES)}")

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
