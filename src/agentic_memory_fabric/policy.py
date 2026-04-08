"""Policy context and trust-gated retrieval decisions."""

from __future__ import annotations

from dataclasses import dataclass, field

from .decay import DecayPolicy, evaluate_freshness
from .replay import LIFECYCLE_DELETED, MemoryState


OVERRIDE_CAPABILITY = "override_retrieval_denials"
OVERRIDE_ROLES = frozenset({"auditor", "debug"})
ATTESTATION_TRUST_LEVELS = ("low", "medium", "high")
_ATTESTATION_TRUST_RANK = {level: idx for idx, level in enumerate(ATTESTATION_TRUST_LEVELS)}
NON_OVERRIDABLE_DENIALS = frozenset(
    {"tenant_scope_required_default_deny", "tenant_scope_mismatch_default_deny"}
)


@dataclass(frozen=True)
class PolicyContext:
    role: str = "runtime"
    capabilities: frozenset[str] = field(default_factory=frozenset)
    allow_overrides: bool = False
    tenant_id: str | None = None
    trusted_subject: bool = False
    current_tick: int | None = None
    decay_policy: DecayPolicy | None = None
    require_attestation: bool = False
    min_attestation_trust_level: str | None = None
    allowed_attestation_issuers: frozenset[str] = field(default_factory=frozenset)
    uncertainty_score: float | None = None
    uncertainty_threshold: float | None = None
    uncertainty_reason: str | None = None
    allow_low_uncertainty_override: bool = False

    def can_override(self) -> bool:
        if not self.trusted_subject:
            return False
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


@dataclass(frozen=True)
class QueryGateDecision:
    allowed: bool
    denial_reason: str | None = None
    override_used: bool = False


def evaluate_query_gate(policy_context: PolicyContext) -> QueryGateDecision:
    threshold = policy_context.uncertainty_threshold
    if threshold is None:
        return QueryGateDecision(allowed=True)

    denial_reason: str | None = None
    score = policy_context.uncertainty_score
    if score is None:
        denial_reason = "uncertainty_signal_required_default_deny"
    elif score < threshold:
        denial_reason = "uncertainty_below_threshold_default_deny"

    if denial_reason is None:
        return QueryGateDecision(allowed=True)

    if policy_context.allow_low_uncertainty_override and policy_context.can_override():
        return QueryGateDecision(
            allowed=True,
            denial_reason=denial_reason,
            override_used=True,
        )
    return QueryGateDecision(allowed=False, denial_reason=denial_reason)


def evaluate_retrieval_policy(state: MemoryState, policy_context: PolicyContext) -> PolicyDecision:
    denial_reason: str | None = None
    if (
        policy_context.min_attestation_trust_level is not None
        and policy_context.min_attestation_trust_level not in _ATTESTATION_TRUST_RANK
    ):
        raise ValueError(
            "min_attestation_trust_level must be one of "
            f"{list(ATTESTATION_TRUST_LEVELS)} when provided"
        )

    if policy_context.tenant_id is None:
        denial_reason = "tenant_scope_required_default_deny"
    elif state.tenant_id != policy_context.tenant_id:
        denial_reason = "tenant_scope_mismatch_default_deny"
    if denial_reason is None and state.lifecycle_state == LIFECYCLE_DELETED:
        denial_reason = "deleted_memory_default_deny"
    if denial_reason is None and state.trust_state == "quarantined":
        denial_reason = "quarantined_memory_default_deny"
    if denial_reason is None and state.trust_state == "expired":
        denial_reason = "expired_memory_default_deny"
    if denial_reason is None and policy_context.decay_policy is not None:
        if policy_context.current_tick is None:
            raise ValueError("current_tick is required when decay_policy is configured")
        freshness_tick = (
            state.last_recall_tick
            if state.last_recall_tick is not None
            else (
                state.last_write_tick
                if state.last_write_tick is not None
                else state.last_tick
            )
        )
        freshness = evaluate_freshness(
            policy=policy_context.decay_policy,
            current_tick=policy_context.current_tick,
            last_tick=freshness_tick,
        )
        if not freshness.is_fresh:
            denial_reason = "decay_expired_default_deny"
    if denial_reason is None and policy_context.require_attestation and not state.has_attestation:
        denial_reason = "attestation_required_default_deny"
    if (
        denial_reason is None
        and policy_context.min_attestation_trust_level is not None
        and (
            not state.has_attestation
            or state.attestation_trust_level is None
            or _ATTESTATION_TRUST_RANK[state.attestation_trust_level]
            < _ATTESTATION_TRUST_RANK[policy_context.min_attestation_trust_level]
        )
    ):
        denial_reason = "attestation_trust_level_default_deny"
    if (
        denial_reason is None
        and policy_context.allowed_attestation_issuers
        and (
            not state.has_attestation
            or state.attestation_issuer is None
            or state.attestation_issuer not in policy_context.allowed_attestation_issuers
        )
    ):
        denial_reason = "attestation_issuer_default_deny"
    if denial_reason is None and state.signature_state == "unsigned":
        denial_reason = "signature_missing_default_deny"
    if denial_reason is None and state.signature_state == "key_missing":
        denial_reason = "signature_key_missing_default_deny"
    if denial_reason is None and state.signature_state == "revoked":
        denial_reason = "signature_key_revoked_default_deny"
    if denial_reason is None and state.signature_state == "invalid":
        denial_reason = "signature_invalid_default_deny"

    if denial_reason is None:
        return PolicyDecision(allowed=True, why_sound="trusted_active_under_policy")

    if denial_reason in NON_OVERRIDABLE_DENIALS:
        return PolicyDecision(
            allowed=False, why_sound="policy_denied", denial_reason=denial_reason
        )

    if policy_context.can_override():
        return PolicyDecision(
            allowed=True,
            why_sound=f"override:{denial_reason}",
            denial_reason=denial_reason,
            override_used=True,
        )
    return PolicyDecision(
        allowed=False, why_sound="policy_denied", denial_reason=denial_reason
    )
