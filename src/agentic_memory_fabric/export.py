"""Snapshot and provenance export helpers."""

from __future__ import annotations

from typing import Any, Iterable

from .events import EventEnvelope
from .policy import PolicyContext
from .replay import MemoryState
from .retrieval import query


def export_sbom_snapshot(
    state_map: dict[str, MemoryState],
    policy_context: PolicyContext,
) -> dict[str, Any]:
    """Export the sound set under policy as a stable snapshot artifact."""
    records = query(state_map, policy_context)
    snapshot_records = [
        {
            "memory_id": record.memory_id,
            "tenant_id": record.tenant_id,
            "memory_class": record.memory_class,
            "trust_state": record.trust_state,
            "version": record.version,
            "last_event_id": record.last_event_id,
            "why_sound": record.why_sound,
            "lifecycle_state": record.lifecycle_state,
            "signature_state": record.signature_state,
            "lineage_depth": record.lineage_depth,
            "recall_count": record.recall_count,
            "reconsolidation_count": record.reconsolidation_count,
            "last_access_tick": record.last_access_tick,
            "last_recall_tick": record.last_recall_tick,
            "last_write_tick": record.last_write_tick,
            "queryable_payload_present": record.queryable_payload_present,
            "promotion_score": record.promotion_score,
            "promotion_eligible": record.promotion_eligible,
            "promoted_from_memory_ids": list(record.promoted_from_memory_ids),
            "reinforcement_score": record.reinforcement_score,
            "conflict_score": record.conflict_score,
            "related_memory_ids": list(record.related_memory_ids),
            "conflicted_memory_ids": list(record.conflicted_memory_ids),
            "conflict_open": record.conflict_open,
            "merged_into_memory_id": record.merged_into_memory_id,
            "superseded_by_memory_id": record.superseded_by_memory_id,
            "resolved_from_memory_ids": list(record.resolved_from_memory_ids),
            "denial_reason": record.denial_reason,
            "override_used": record.override_used,
        }
        for record in records
    ]
    return {
        "artifact_type": "memory_sbom_snapshot",
        "count": len(snapshot_records),
        "records": snapshot_records,
    }


def export_provenance_log(
    events: Iterable[EventEnvelope],
    sequence_range: tuple[int, int] | None = None,
    memory_id: str | None = None,
    tenant_id: str | None = None,
) -> dict[str, Any]:
    """Export append-only provenance history with optional sequence/memory filters."""
    if sequence_range is not None:
        start, end = sequence_range
        if start < 1 or end < start:
            raise ValueError("sequence_range must be (start>=1, end>=start)")
    else:
        start = end = None

    selected_events = []
    for event in sorted(events, key=lambda item: item.sequence):
        if memory_id is not None and event.memory_id != memory_id:
            continue
        if tenant_id is not None and event.tenant_id != tenant_id:
            continue
        if start is not None and (event.sequence < start or event.sequence > end):
            continue
        selected_events.append(event.to_dict())

    out: dict[str, Any] = {
        "artifact_type": "provenance_log_slice",
        "count": len(selected_events),
        "events": selected_events,
    }
    if sequence_range is not None:
        out["sequence_range"] = {"start": start, "end": end}
    if memory_id is not None:
        out["memory_id"] = memory_id
    if tenant_id is not None:
        out["tenant_id"] = tenant_id
    return out
