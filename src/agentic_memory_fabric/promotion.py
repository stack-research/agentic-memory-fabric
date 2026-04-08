"""Promotion scoring helpers for explicit multi-timescale memory."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol

from .decay import DecayPolicy, compute_age_ticks, evaluate_freshness


class PromotionStateLike(Protocol):
    memory_id: str
    memory_class: str
    trust_state: str
    lifecycle_state: str
    signature_state: str
    recall_count: int
    last_tick: int
    last_recall_tick: int | None
    last_write_tick: int | None
    queryable_payload_present: bool
    has_attestation: bool


@dataclass(frozen=True)
class PromotionAssessment:
    memory_id: str
    tenant_id: str | None
    memory_class: str | None
    source_event_id: str | None
    promotion_score: float | None
    promotion_eligible: bool
    denial_reason: str | None
    override_used: bool
    promoted_from_memory_ids: tuple[str, ...]


def _freshness_tick(state: PromotionStateLike) -> int:
    if state.last_recall_tick is not None:
        return state.last_recall_tick
    if state.last_write_tick is not None:
        return state.last_write_tick
    return state.last_tick


def _freshness_ratio(
    state: PromotionStateLike,
    *,
    current_tick: int | None = None,
    decay_policy: DecayPolicy | None = None,
) -> float:
    freshness_tick = _freshness_tick(state)
    effective_current_tick = state.last_tick if current_tick is None else current_tick
    age_ticks = compute_age_ticks(current_tick=effective_current_tick, last_tick=freshness_tick)
    if decay_policy is not None and decay_policy.max_age_ticks > 0:
        freshness = evaluate_freshness(
            policy=decay_policy,
            current_tick=effective_current_tick,
            last_tick=freshness_tick,
        )
        if not freshness.is_fresh:
            return 0.0
        return max(0.0, 1.0 - (freshness.age_ticks / decay_policy.max_age_ticks))
    return max(0.0, 1.0 - min(age_ticks, 20) / 20.0)


def compute_promotion_score(
    state: PromotionStateLike,
    *,
    current_tick: int | None = None,
    decay_policy: DecayPolicy | None = None,
) -> float:
    if state.memory_class != "episodic":
        return 0.0
    recall_ratio = min(state.recall_count, 5) / 5.0
    freshness_ratio = _freshness_ratio(
        state,
        current_tick=current_tick,
        decay_policy=decay_policy,
    )
    if state.signature_state == "verified":
        trust_ratio = 1.0
    elif state.has_attestation:
        trust_ratio = 0.6
    else:
        trust_ratio = 0.0
    payload_ratio = 1.0 if state.queryable_payload_present else 0.0
    score = (
        0.4 * recall_ratio
        + 0.25 * freshness_ratio
        + 0.2 * trust_ratio
        + 0.15 * payload_ratio
    )
    return round(score, 6)


def compute_promotion_eligible(
    state: PromotionStateLike,
    *,
    current_tick: int | None = None,
    decay_policy: DecayPolicy | None = None,
) -> bool:
    if state.memory_class != "episodic":
        return False
    if state.lifecycle_state != "active":
        return False
    if state.trust_state != "trusted":
        return False
    if not state.queryable_payload_present:
        return False
    if state.signature_state != "verified":
        return False
    if decay_policy is not None:
        return _freshness_ratio(
            state,
            current_tick=current_tick,
            decay_policy=decay_policy,
        ) > 0.0
    return True
