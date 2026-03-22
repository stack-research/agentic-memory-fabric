"""Lineage explanation helpers for memory event streams."""

from __future__ import annotations

from typing import Any, Iterable

from .events import EventEnvelope


def explain(
    memory_id: str,
    events: Iterable[EventEnvelope],
    *,
    tenant_id: str | None = None,
) -> list[dict[str, Any]]:
    """Return a deterministic, compact lineage trace for a memory."""
    scoped_events = sorted(
        (
            event
            for event in events
            if event.memory_id == memory_id and (tenant_id is None or event.tenant_id == tenant_id)
        ),
        key=lambda event: event.sequence,
    )

    trace: list[dict[str, Any]] = []
    for event in scoped_events:
        entry: dict[str, Any] = {
            "event_id": event.event_id,
            "sequence": event.sequence,
            "event_type": event.event_type,
            "actor": event.actor.to_dict(),
            "tenant_id": event.tenant_id,
            "previous_events": list(event.previous_events),
            "timestamp": event.timestamp.to_dict(),
        }
        if event.trust_transition is not None:
            entry["trust_transition"] = event.trust_transition.to_dict()
        trace.append(entry)

    return trace
