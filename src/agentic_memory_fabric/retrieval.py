"""Minimal trust-gated retrieval APIs over materialized state."""

from __future__ import annotations

from dataclasses import dataclass

from .policy import PolicyContext, evaluate_retrieval_policy
from .replay import MemoryState


@dataclass(frozen=True)
class RetrievalRecord:
    memory_id: str
    tenant_id: str
    trust_state: str
    version: int
    last_event_id: str
    why_sound: str
    lifecycle_state: str
    signature_state: str
    denial_reason: str | None
    override_used: bool


def _to_retrieval_record(state: MemoryState, *, why_sound: str, denial_reason: str | None, override_used: bool) -> RetrievalRecord:
    return RetrievalRecord(
        memory_id=state.memory_id,
        tenant_id=state.tenant_id,
        trust_state=state.trust_state,
        version=state.version,
        last_event_id=state.last_event_id,
        why_sound=why_sound,
        lifecycle_state=state.lifecycle_state,
        signature_state=state.signature_state,
        denial_reason=denial_reason,
        override_used=override_used,
    )


def get(
    memory_id: str,
    state_map: dict[str, MemoryState],
    policy_context: PolicyContext,
) -> RetrievalRecord | None:
    state = state_map.get(memory_id)
    if state is None:
        return None

    decision = evaluate_retrieval_policy(state, policy_context)
    if not decision.allowed:
        return None
    return _to_retrieval_record(
        state,
        why_sound=decision.why_sound,
        denial_reason=decision.denial_reason,
        override_used=decision.override_used,
    )


def query(
    state_map: dict[str, MemoryState],
    policy_context: PolicyContext,
    trust_states: set[str] | None = None,
    limit: int | None = None,
) -> list[RetrievalRecord]:
    if limit is not None and limit < 1:
        raise ValueError("limit must be >= 1 when provided")

    records: list[RetrievalRecord] = []
    for state in sorted(state_map.values(), key=lambda item: item.last_sequence, reverse=True):
        if trust_states is not None and state.trust_state not in trust_states:
            continue
        decision = evaluate_retrieval_policy(state, policy_context)
        if not decision.allowed:
            continue
        records.append(
            _to_retrieval_record(
                state,
                why_sound=decision.why_sound,
                denial_reason=decision.denial_reason,
                override_used=decision.override_used,
            )
        )
        if limit is not None and len(records) >= limit:
            break

    return records
