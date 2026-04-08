"""Governed import path for append-only imported events."""

from __future__ import annotations

from typing import Any, Iterable, Mapping
from uuid import NAMESPACE_URL, uuid5

from .events import Actor, EventEnvelope, canonical_payload_hash
from .log import EventLog, SignatureVerifier


def _deterministic_event_id(*, memory_id: str, sequence: int, payload_hash: str, source_ref: str) -> str:
    token = f"imported:{memory_id}:{sequence}:{payload_hash}:{source_ref}"
    return str(uuid5(NAMESPACE_URL, token))


def import_records(
    records: Iterable[Mapping[str, Any]],
    *,
    actor: Mapping[str, Any] | Actor,
    start_sequence: int,
    default_timestamp: str,
    default_tick: int | None = None,
    tenant_id: str | None = None,
) -> tuple[EventEnvelope, ...]:
    """Convert source records into deterministic imported EventEnvelope objects."""
    if start_sequence < 1:
        raise ValueError("start_sequence must be >= 1")
    if not default_timestamp:
        raise ValueError("default_timestamp is required")

    actor_dict = actor.to_dict() if isinstance(actor, Actor) else dict(actor)
    source_records = list(records)
    imported_events: list[EventEnvelope] = []
    latest_event_per_memory: dict[str, str] = {}

    for idx, record in enumerate(source_records):
        sequence = start_sequence + idx
        memory_id = str(record.get("memory_id", "")).strip()
        if not memory_id:
            raise ValueError("Each import record must include memory_id")
        event_tenant_id = str(record.get("tenant_id", tenant_id or "")).strip()
        if not event_tenant_id:
            raise ValueError("Each import record must include tenant_id")

        payload = record.get("payload", {})
        payload_hash = record.get("payload_hash")
        if payload_hash is None:
            payload_hash = canonical_payload_hash(payload)

        explicit_previous = record.get("previous_events")
        if explicit_previous is None:
            previous_events: list[str] = []
            if memory_id in latest_event_per_memory:
                previous_events = [latest_event_per_memory[memory_id]]
        else:
            previous_events = list(explicit_previous)

        source_id = str(record.get("source_id", f"record-{idx}"))
        evidence_refs = record.get("evidence_refs")
        if evidence_refs is None:
            evidence_refs = [{"type": "opaque", "ref": f"import:{source_id}"}]

        timestamp = record.get("timestamp") or {"wall_time": default_timestamp}
        if "tick" not in timestamp:
            timestamp["tick"] = (
                default_tick + idx if default_tick is not None else sequence
            )

        event_id = record.get("event_id")
        if event_id is None:
            event_id = _deterministic_event_id(
                memory_id=memory_id,
                sequence=sequence,
                payload_hash=payload_hash,
                source_ref=evidence_refs[0]["ref"],
            )

        event_data: dict[str, Any] = {
            "event_id": event_id,
            "sequence": sequence,
            "timestamp": timestamp,
            "actor": actor_dict,
            "tenant_id": event_tenant_id,
            "memory_id": memory_id,
            "event_type": "imported",
            "previous_events": previous_events,
            "payload_hash": payload_hash,
            "evidence_refs": evidence_refs,
        }
        if "payload" in record:
            event_data["payload"] = payload
        if "memory_class" in record:
            event_data["memory_class"] = record["memory_class"]
        if "trust_transition" in record:
            event_data["trust_transition"] = record["trust_transition"]
        if "signature" in record:
            event_data["signature"] = record["signature"]
        if "attestation" in record:
            event_data["attestation"] = record["attestation"]

        event = EventEnvelope.from_dict(event_data)
        imported_events.append(event)
        latest_event_per_memory[memory_id] = event.event_id

    return tuple(imported_events)


def append_imported_records(
    log: EventLog,
    records: Iterable[Mapping[str, Any]],
    *,
    actor: Mapping[str, Any] | Actor,
    start_sequence: int,
    default_timestamp: str,
    default_tick: int | None = None,
    tenant_id: str | None = None,
    signature_verifier: SignatureVerifier | None = None,
) -> tuple[EventEnvelope, ...]:
    """Import records and append them to the event log as imported events."""
    events = import_records(
        records,
        actor=actor,
        start_sequence=start_sequence,
        default_timestamp=default_timestamp,
        default_tick=default_tick,
        tenant_id=tenant_id,
    )
    for event in events:
        log.append(event, signature_verifier=signature_verifier)
    return events
