"""Agentic Memory Fabric control-plane package."""

from .crypto import (
    KEY_STATUS_ACTIVE,
    KEY_STATUS_REVOKED,
    KeyMaterial,
    SUPPORTED_SIGNATURE_ALGS,
    SignatureState,
    canonicalize_event_for_signing,
    sign_event,
    verify_event_signature,
)
from .events import (
    Actor,
    Attestation,
    canonical_json_dumps,
    canonical_payload_hash,
    DEFAULT_MEMORY_CLASS,
    EventEnvelope,
    EventSignature,
    EventTimestamp,
    EvidenceRef,
    payload_to_retrieval_text,
    TrustTransition,
    VALID_MEMORY_CLASSES,
    validate_event_envelope,
)
from .decay import DecayPolicy, FreshnessDecision, compute_age_ticks, evaluate_freshness
from .explain import explain
from .export import export_provenance_log, export_sbom_snapshot
from .graph import (
    DEFAULT_EDGE_WEIGHT,
    GRAPH_EXPANDABLE_EDGE_KINDS,
    conflict_penalty,
    direct_retrieval_score,
    expanded_retrieval_score,
    normalized_edge_weight,
    recency_bonus,
    reinforcement_bonus,
)
from .importer import append_imported_records, import_records
from .log import AppendOnlyEventLog, EventLog
from .policy import (
    ATTESTATION_TRUST_LEVELS,
    PolicyContext,
    PolicyDecision,
    QueryGateDecision,
    evaluate_query_gate,
    evaluate_retrieval_policy,
)
from .promotion import PromotionAssessment, compute_promotion_eligible, compute_promotion_score
from .query_index import InMemoryQueryIndex, QueryIndex, QueryIndexEntry, SearchHit
from .replay import MemoryState, replay_events
from .retrieval import (
    GetOutcome,
    QueryAuditSummary,
    RetrievalRecord,
    get,
    get_outcome,
    peek,
    query,
    query_with_summary,
)
from .runtime import AuditSink, MemoryRuntime, open_runtime
from .service import ServiceApp, run_http_server
from .sqlite_store import SQLiteEventLog


def run_cli(*args: object, **kwargs: object) -> int:
    """Lazily import CLI to avoid runpy double-import warnings."""
    from .cli import run_cli as _run_cli

    return _run_cli(*args, **kwargs)


__all__ = [
    "Actor",
    "AppendOnlyEventLog",
    "AuditSink",
    "Attestation",
    "ATTESTATION_TRUST_LEVELS",
    "canonical_json_dumps",
    "canonical_payload_hash",
    "compute_promotion_eligible",
    "compute_promotion_score",
    "conflict_penalty",
    "DEFAULT_MEMORY_CLASS",
    "DEFAULT_EDGE_WEIGHT",
    "GetOutcome",
    "DecayPolicy",
    "EventLog",
    "EventEnvelope",
    "EventSignature",
    "EventTimestamp",
    "EvidenceRef",
    "FreshnessDecision",
    "GRAPH_EXPANDABLE_EDGE_KINDS",
    "KeyMaterial",
    "KEY_STATUS_ACTIVE",
    "KEY_STATUS_REVOKED",
    "MemoryState",
    "InMemoryQueryIndex",
    "PolicyContext",
    "PolicyDecision",
    "PromotionAssessment",
    "QueryIndex",
    "QueryIndexEntry",
    "QueryGateDecision",
    "QueryAuditSummary",
    "RetrievalRecord",
    "SUPPORTED_SIGNATURE_ALGS",
    "SignatureState",
    "SearchHit",
    "TrustTransition",
    "VALID_MEMORY_CLASSES",
    "canonicalize_event_for_signing",
    "compute_age_ticks",
    "direct_retrieval_score",
    "evaluate_retrieval_policy",
    "evaluate_query_gate",
    "evaluate_freshness",
    "explain",
    "expanded_retrieval_score",
    "export_provenance_log",
    "export_sbom_snapshot",
    "get",
    "get_outcome",
    "MemoryRuntime",
    "SQLiteEventLog",
    "ServiceApp",
    "append_imported_records",
    "import_records",
    "query",
    "query_with_summary",
    "replay_events",
    "run_cli",
    "run_http_server",
    "normalized_edge_weight",
    "open_runtime",
    "payload_to_retrieval_text",
    "peek",
    "recency_bonus",
    "reinforcement_bonus",
    "sign_event",
    "validate_event_envelope",
    "verify_event_signature",
]
