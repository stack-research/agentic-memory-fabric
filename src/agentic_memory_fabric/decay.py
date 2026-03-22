"""Deterministic decay/TTL policy helpers."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class DecayPolicy:
    max_age_ticks: int
    half_life_ticks: int | None = None

    def __post_init__(self) -> None:
        if self.max_age_ticks < 0:
            raise ValueError("max_age_ticks must be >= 0")
        if self.half_life_ticks is not None and self.half_life_ticks <= 0:
            raise ValueError("half_life_ticks must be > 0 when provided")


@dataclass(frozen=True)
class FreshnessDecision:
    is_fresh: bool
    age_ticks: int
    reason: str


def compute_age_ticks(current_tick: int, last_tick: int) -> int:
    if current_tick < 0 or last_tick < 0:
        raise ValueError("current_tick and last_tick must be >= 0")
    if current_tick < last_tick:
        raise ValueError("current_tick must be >= last_tick")
    return current_tick - last_tick


def evaluate_freshness(
    *,
    policy: DecayPolicy,
    current_tick: int,
    last_tick: int,
) -> FreshnessDecision:
    age_ticks = compute_age_ticks(current_tick=current_tick, last_tick=last_tick)
    if age_ticks > policy.max_age_ticks:
        return FreshnessDecision(
            is_fresh=False,
            age_ticks=age_ticks,
            reason="expired_by_decay",
        )
    return FreshnessDecision(
        is_fresh=True,
        age_ticks=age_ticks,
        reason="fresh_under_decay_policy",
    )
