"""Policy context and trust-gated retrieval decisions."""

from __future__ import annotations

from dataclasses import dataclass, field

from .replay import LIFECYCLE_DELETED, MemoryState


OVERRIDE_CAPABILITY = "override_retrieval_denials"
OVERRIDE_ROLES = frozenset({"auditor", "debug"})


@dataclass(frozen=True)
class PolicyContext:
    role: str = "runtime"
    capabilities: frozenset[str] = field(default_factory=frozenset)
    allow_overrides: bool = False

    def can_override(self) -> bool:
        return (
            self.allow_overrides
            or self.role in OVERRIDE_ROLES
            or OVERRIDE_CAPABILITY in self.capabilities
        )


@dataclass(frozen=True)
class PolicyDecision:
    allowed: bool
    why_sound: str
    denial_reason: str | None = None
    override_used: bool = False


def evaluate_retrieval_policy(state: MemoryState, policy_context: PolicyContext) -> PolicyDecision:
    denial_reason: str | None = None

    if state.lifecycle_state == LIFECYCLE_DELETED:
        denial_reason = "deleted_memory_default_deny"
    elif state.trust_state == "quarantined":
        denial_reason = "quarantined_memory_default_deny"
    elif state.trust_state == "expired":
        denial_reason = "expired_memory_default_deny"

    if denial_reason is None:
        return PolicyDecision(allowed=True, why_sound="trusted_active_under_policy")

    if policy_context.can_override():
        return PolicyDecision(
            allowed=True,
            why_sound=f"override:{denial_reason}",
            denial_reason=denial_reason,
            override_used=True,
        )

    return PolicyDecision(allowed=False, why_sound="policy_denied", denial_reason=denial_reason)
