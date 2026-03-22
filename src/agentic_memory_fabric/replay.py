"""Deterministic replay fold for AMF event streams."""

from __future__ import annotations

from dataclasses import dataclass

from .events import EventEnvelope


TRUSTED_EVENT_TYPES = {"created", "updated", "released", "imported", "attested"}
LIFECYCLE_ACTIVE = "active"
LIFECYCLE_DELETED = "deleted"


@dataclass(frozen=True)
class MemoryState:
    memory_id: str
    version: int
    trust_state: str
    lifecycle_state: str
    last_event_id: str
    last_sequence: int
    last_event_type: str
    last_tick: int
    payload_hash: str
    previous_events: tuple[str, ...]


def replay_events(events: tuple[EventEnvelope, ...] | list[EventEnvelope]) -> dict[str, MemoryState]:
    materialized: dict[str, MemoryState] = {}

    for event in events:
        existing = materialized.get(event.memory_id)
        version = 1 if existing is None else existing.version + 1
        lifecycle_state = LIFECYCLE_ACTIVE if existing is None else existing.lifecycle_state
        trust_state = "trusted" if existing is None else existing.trust_state

        if event.event_type == "quarantined":
            trust_state = "quarantined"
        elif event.event_type == "expired":
            trust_state = "expired"
        elif event.event_type in TRUSTED_EVENT_TYPES:
            trust_state = "trusted"
        elif event.event_type == "deleted":
            lifecycle_state = LIFECYCLE_DELETED

        if event.trust_transition is not None:
            trust_state = event.trust_transition.to

        materialized[event.memory_id] = MemoryState(
            memory_id=event.memory_id,
            version=version,
            trust_state=trust_state,
            lifecycle_state=lifecycle_state,
            last_event_id=event.event_id,
            last_sequence=event.sequence,
            last_event_type=event.event_type,
            # Prefer explicit logical tick and fall back to sequence for deterministic clocking.
            last_tick=event.timestamp.tick if event.timestamp.tick is not None else event.sequence,
            payload_hash=event.payload_hash,
            previous_events=event.previous_events,
        )

    return materialized
