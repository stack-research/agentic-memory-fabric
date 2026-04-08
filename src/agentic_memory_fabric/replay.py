"""Deterministic replay fold for AMF event streams."""

from __future__ import annotations

from dataclasses import dataclass

from .events import EventEnvelope, payload_to_retrieval_text


TRUSTED_EVENT_TYPES = {
    "created",
    "updated",
    "released",
    "imported",
    "attested",
    "reconsolidated",
}
CONTENT_VERSION_EVENT_TYPES = {"created", "updated", "imported", "reconsolidated"}
LIFECYCLE_ACTIVE = "active"
LIFECYCLE_DELETED = "deleted"


@dataclass(frozen=True)
class MemoryState:
    memory_id: str
    tenant_id: str
    version: int
    trust_state: str
    lifecycle_state: str
    last_event_id: str
    last_sequence: int
    last_event_type: str
    signature_state: str
    last_tick: int
    payload_hash: str
    payload: object | None = None
    retrieval_text: str | None = None
    queryable_payload_present: bool = False
    previous_events: tuple[str, ...] = ()
    lineage_depth: int = 0
    recall_count: int = 0
    reconsolidation_count: int = 0
    last_access_tick: int | None = None
    last_recall_tick: int | None = None
    last_write_tick: int | None = None
    has_attestation: bool = False
    attestation_trust_level: str | None = None
    attestation_issuer: str | None = None


def replay_events(
    events: tuple[EventEnvelope, ...] | list[EventEnvelope],
    *,
    signature_states: dict[str, str] | None = None,
) -> dict[str, MemoryState]:
    materialized: dict[str, MemoryState] = {}

    for event in events:
        existing = materialized.get(event.memory_id)
        version = 0 if existing is None else existing.version
        lifecycle_state = LIFECYCLE_ACTIVE if existing is None else existing.lifecycle_state
        trust_state = "trusted" if existing is None else existing.trust_state
        lineage_depth = 0 if existing is None else existing.lineage_depth
        recall_count = 0 if existing is None else existing.recall_count
        reconsolidation_count = 0 if existing is None else existing.reconsolidation_count
        last_access_tick = None if existing is None else existing.last_access_tick
        last_recall_tick = None if existing is None else existing.last_recall_tick
        last_write_tick = None if existing is None else existing.last_write_tick
        payload = None if existing is None else existing.payload
        retrieval_text = None if existing is None else existing.retrieval_text
        queryable_payload_present = (
            False if existing is None else existing.queryable_payload_present
        )
        current_tick = event.timestamp.tick if event.timestamp.tick is not None else event.sequence

        if event.event_type in CONTENT_VERSION_EVENT_TYPES:
            version += 1
            last_write_tick = current_tick
            last_access_tick = current_tick
            payload = event.payload
            retrieval_text = payload_to_retrieval_text(event.payload)
            queryable_payload_present = event.payload is not None and retrieval_text is not None

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

        if event.event_type == "recalled":
            recall_count += 1
            last_access_tick = current_tick
            last_recall_tick = current_tick
        elif event.event_type == "reconsolidated":
            reconsolidation_count += 1
            last_access_tick = current_tick
            last_recall_tick = current_tick

        lineage_depth += 1

        if (
            existing is not None
            and event.event_type in {"recalled", "reconsolidated"}
            and event.signature is None
        ):
            signature_state = existing.signature_state
        else:
            signature_state = (
                signature_states[event.event_id]
                if signature_states is not None and event.event_id in signature_states
                else ("unsigned" if event.signature is None else "invalid")
            )

        materialized[event.memory_id] = MemoryState(
            memory_id=event.memory_id,
            tenant_id=event.tenant_id,
            version=version,
            trust_state=trust_state,
            lifecycle_state=lifecycle_state,
            last_event_id=event.event_id,
            last_sequence=event.sequence,
            last_event_type=event.event_type,
            signature_state=signature_state,
            # Prefer explicit logical tick and fall back to sequence for deterministic clocking.
            last_tick=current_tick,
            payload_hash=event.payload_hash,
            payload=payload,
            retrieval_text=retrieval_text,
            queryable_payload_present=queryable_payload_present,
            previous_events=event.previous_events,
            lineage_depth=lineage_depth,
            recall_count=recall_count,
            reconsolidation_count=reconsolidation_count,
            last_access_tick=last_access_tick,
            last_recall_tick=last_recall_tick,
            last_write_tick=last_write_tick,
            has_attestation=event.attestation is not None,
            attestation_trust_level=(
                event.attestation.trust_level if event.attestation is not None else None
            ),
            attestation_issuer=event.attestation.issuer if event.attestation is not None else None,
        )

    return materialized
