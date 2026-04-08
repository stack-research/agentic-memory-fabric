"""Minimal trust-gated retrieval APIs over materialized state."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

from .policy import PolicyContext, evaluate_retrieval_policy
from .replay import MemoryState


@dataclass(frozen=True)
class RetrievalRecord:
    memory_id: str
    tenant_id: str
    memory_class: str
    trust_state: str
    version: int
    last_event_id: str
    why_sound: str
    lifecycle_state: str
    signature_state: str
    lineage_depth: int
    recall_count: int
    reconsolidation_count: int
    last_access_tick: int | None
    last_recall_tick: int | None
    last_write_tick: int | None
    queryable_payload_present: bool
    promotion_score: float
    promotion_eligible: bool
    promoted_from_memory_ids: tuple[str, ...]
    reinforcement_score: float
    conflict_score: float
    related_memory_ids: tuple[str, ...]
    conflicted_memory_ids: tuple[str, ...]
    conflict_open: bool
    merged_into_memory_id: str | None
    superseded_by_memory_id: str | None
    resolved_from_memory_ids: tuple[str, ...]
    retrieval_score: float | None
    retrieval_mode: str | None
    indexed_event_id: str | None
    denial_reason: str | None
    override_used: bool


@dataclass(frozen=True)
class QueryAuditSummary:
    considered: int
    allowed: int
    trust_state_filtered: int
    override_used_count: int
    denied_by_reason: dict[str, int]


@dataclass(frozen=True)
class GetOutcome:
    outcome: Literal["allowed", "denied", "not_found"]
    record: RetrievalRecord | None = None
    denial_reason: str | None = None


def to_retrieval_record(
    state: MemoryState,
    *,
    why_sound: str,
    denial_reason: str | None,
    override_used: bool,
    retrieval_score: float | None = None,
    retrieval_mode: str | None = None,
    indexed_event_id: str | None = None,
) -> RetrievalRecord:
    return RetrievalRecord(
        memory_id=state.memory_id,
        tenant_id=state.tenant_id,
        memory_class=state.memory_class,
        trust_state=state.trust_state,
        version=state.version,
        last_event_id=state.last_event_id,
        why_sound=why_sound,
        lifecycle_state=state.lifecycle_state,
        signature_state=state.signature_state,
        lineage_depth=state.lineage_depth,
        recall_count=state.recall_count,
        reconsolidation_count=state.reconsolidation_count,
        last_access_tick=state.last_access_tick,
        last_recall_tick=state.last_recall_tick,
        last_write_tick=state.last_write_tick,
        queryable_payload_present=state.queryable_payload_present,
        promotion_score=state.promotion_score,
        promotion_eligible=state.promotion_eligible,
        promoted_from_memory_ids=state.promoted_from_memory_ids,
        reinforcement_score=state.reinforcement_score,
        conflict_score=state.conflict_score,
        related_memory_ids=state.related_memory_ids,
        conflicted_memory_ids=state.conflicted_memory_ids,
        conflict_open=state.conflict_open,
        merged_into_memory_id=state.merged_into_memory_id,
        superseded_by_memory_id=state.superseded_by_memory_id,
        resolved_from_memory_ids=state.resolved_from_memory_ids,
        retrieval_score=retrieval_score,
        retrieval_mode=retrieval_mode,
        indexed_event_id=indexed_event_id,
        denial_reason=denial_reason,
        override_used=override_used,
    )


def get_outcome(
    memory_id: str,
    state_map: dict[str, MemoryState],
    policy_context: PolicyContext,
) -> GetOutcome:
    state = state_map.get(memory_id)
    if state is None:
        return GetOutcome(outcome="not_found")

    decision = evaluate_retrieval_policy(state, policy_context)
    if not decision.allowed:
        return GetOutcome(
            outcome="denied",
            denial_reason=decision.denial_reason,
        )
    record = to_retrieval_record(
        state,
        why_sound=decision.why_sound,
        denial_reason=decision.denial_reason,
        override_used=decision.override_used,
    )
    return GetOutcome(
        outcome="allowed",
        record=record,
        denial_reason=decision.denial_reason,
    )


def get(
    memory_id: str,
    state_map: dict[str, MemoryState],
    policy_context: PolicyContext,
) -> RetrievalRecord | None:
    outcome = get_outcome(memory_id, state_map, policy_context)
    return outcome.record if outcome.outcome == "allowed" else None


def peek(
    memory_id: str,
    state_map: dict[str, MemoryState],
    policy_context: PolicyContext,
) -> RetrievalRecord | None:
    return get(memory_id, state_map, policy_context)


def query_with_summary(
    state_map: dict[str, MemoryState],
    policy_context: PolicyContext,
    trust_states: set[str] | None = None,
    limit: int | None = None,
) -> tuple[list[RetrievalRecord], QueryAuditSummary]:
    if limit is not None and limit < 1:
        raise ValueError("limit must be >= 1 when provided")

    records: list[RetrievalRecord] = []
    considered = 0
    trust_state_filtered = 0
    override_used_count = 0
    denied_by_reason: dict[str, int] = {}
    for state in sorted(state_map.values(), key=lambda item: item.last_sequence, reverse=True):
        considered += 1
        if trust_states is not None and state.trust_state not in trust_states:
            trust_state_filtered += 1
            continue
        decision = evaluate_retrieval_policy(state, policy_context)
        if not decision.allowed:
            reason = decision.denial_reason or "policy_denied"
            denied_by_reason[reason] = denied_by_reason.get(reason, 0) + 1
            continue
        if decision.override_used:
            override_used_count += 1
        records.append(
            to_retrieval_record(
                state,
                why_sound=decision.why_sound,
                denial_reason=decision.denial_reason,
                override_used=decision.override_used,
            )
        )
        if limit is not None and len(records) >= limit:
            break

    return (
        records,
        QueryAuditSummary(
            considered=considered,
            allowed=len(records),
            trust_state_filtered=trust_state_filtered,
            override_used_count=override_used_count,
            denied_by_reason=denied_by_reason,
        ),
    )


def query(
    state_map: dict[str, MemoryState],
    policy_context: PolicyContext,
    trust_states: set[str] | None = None,
    limit: int | None = None,
) -> list[RetrievalRecord]:
    records, _summary = query_with_summary(
        state_map,
        policy_context,
        trust_states=trust_states,
        limit=limit,
    )
    return records
