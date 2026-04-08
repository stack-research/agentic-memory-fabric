"""Deterministic graph-scoring helpers for AMF."""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .replay import MemoryState


DEFAULT_EDGE_WEIGHT = 1.0
GRAPH_EXPANDABLE_EDGE_KINDS = frozenset({"linked", "reinforced"})


def normalized_edge_weight(value: float | None) -> float:
    if value is None:
        return DEFAULT_EDGE_WEIGHT
    return float(value)


def recency_bonus(
    state: MemoryState,
    *,
    reference_tick: int,
) -> float:
    freshness_tick = (
        state.last_recall_tick
        if state.last_recall_tick is not None
        else (state.last_write_tick if state.last_write_tick is not None else state.last_tick)
    )
    age = max(reference_tick - freshness_tick, 0)
    return max(0.0, 0.2 - (age * 0.01))


def reinforcement_bonus(state: MemoryState) -> float:
    return min(state.reinforcement_score * 0.05, 0.25)


def conflict_penalty(state: MemoryState) -> float:
    return min(state.conflict_score * 0.08, 0.4)


def direct_retrieval_score(
    *,
    lexical_score: float,
    state: MemoryState,
    reference_tick: int,
) -> float:
    score = lexical_score + recency_bonus(state, reference_tick=reference_tick)
    score += reinforcement_bonus(state)
    score -= conflict_penalty(state)
    return round(max(score, 0.0), 6)


def expanded_retrieval_score(
    *,
    source_score: float,
    target_state: MemoryState,
    edge_kind: str,
    edge_weight: float | None,
    reference_tick: int,
) -> float:
    kind_bonus = 0.12 if edge_kind == "linked" else 0.18 if edge_kind == "reinforced" else -0.1
    weight_bonus = max(normalized_edge_weight(edge_weight) - 1.0, 0.0) * 0.05
    score = (source_score * 0.6) + kind_bonus + weight_bonus
    score += recency_bonus(target_state, reference_tick=reference_tick)
    score += reinforcement_bonus(target_state)
    score -= conflict_penalty(target_state)
    return round(max(score, 0.0), 6)
