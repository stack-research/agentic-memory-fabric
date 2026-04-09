"""In-memory runtime state container for service and CLI surfaces."""

from __future__ import annotations

import time
from datetime import datetime, timezone
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Mapping
from uuid import uuid4

from .crypto import KeyMaterial, verify_event_signature
from .decay import DecayPolicy
from .events import Actor, EventEnvelope, canonical_payload_hash
from .explain import explain
from .export import export_provenance_log, export_sbom_snapshot
from .graph import (
    GRAPH_EXPANDABLE_EDGE_KINDS,
    direct_retrieval_score,
    expanded_retrieval_score,
)
from .importer import append_imported_records
from .log import AppendOnlyEventLog, EventLog, QuerySyncTask
from .policy import (
    ATTESTATION_TRUST_LEVELS,
    PolicyContext,
    evaluate_query_gate,
)
from .pgvector_backend import PgVectorQueryBackend
from .postgres_store import PostgresEventLog
from .postgres_support import PostgresBackendError
from .promotion import PromotionAssessment, compute_promotion_score
from .query_index import (
    DeterministicTextEmbedder,
    InMemoryQueryIndex,
    QueryBackend,
    QueryBackendError,
    QuerySyncError,
    TextEmbedder,
)
from .replay import MemoryState, replay_events
from .resolution import (
    DEFAULT_RESOLVER_KIND,
    ConflictAssessment,
    stable_conflict_set_id,
)
from .retrieval import get_outcome, query_with_summary, to_retrieval_record
from .sqlite_store import SQLiteEventLog

AuditSink = Callable[[Mapping[str, Any]], None]


@dataclass(frozen=True)
class QueryCandidate:
    memory_id: str
    retrieval_score: float
    retrieval_mode: str
    indexed_event_id: str
    expanded_rank: int


@dataclass
class MemoryRuntime:
    log: EventLog = field(default_factory=AppendOnlyEventLog)
    keyring: dict[str, bytes | str | Mapping[str, Any] | KeyMaterial] = field(default_factory=dict)
    audit_sink: AuditSink | None = None
    query_backend_name: str = "inmemory"
    query_backend_dsn: str | None = None
    query_backend_schema: str = "amf_query"
    bootstrap_query_backend: bool = False
    embedder: TextEmbedder | None = None
    _state_cache: dict[str, MemoryState] | None = field(default=None, init=False, repr=False)
    _events_cache: tuple[EventEnvelope, ...] | None = field(default=None, init=False, repr=False)
    _query_index_cache: QueryBackend | None = field(default=None, init=False, repr=False)

    def __post_init__(self) -> None:
        if self.query_backend_name not in {"inmemory", "pgvector"}:
            raise ValueError("query_backend must be 'inmemory' or 'pgvector'")
        if self.embedder is None:
            self.embedder = DeterministicTextEmbedder()
        if self.query_backend_name == "pgvector":
            if self.query_backend_dsn is None:
                raise ValueError("query_backend_dsn is required when query_backend='pgvector'")
            self._query_index_cache = PgVectorQueryBackend(
                dsn=self.query_backend_dsn,
                schema=self.query_backend_schema,
                embedder=self.embedder,
                bootstrap=self.bootstrap_query_backend,
            )
            if len(self.log) > 0:
                self.sync_query_index(full_refresh=self.bootstrap_query_backend)

    def _key_resolver(
        self, key_id: str
    ) -> bytes | str | Mapping[str, Any] | KeyMaterial | None:
        return self.keyring.get(key_id)

    def _signature_verifier(self, event: EventEnvelope) -> str:
        return verify_event_signature(event, key_resolver=self._key_resolver)

    def _build_policy_context(
        self,
        raw: Mapping[str, Any] | None = None,
        *,
        trusted_context: Mapping[str, Any] | None = None,
    ) -> PolicyContext:
        source = raw or {}
        trusted = trusted_context or {}
        decay_policy_raw = source.get("decay_policy")
        decay_policy = None
        if isinstance(decay_policy_raw, Mapping):
            decay_policy = DecayPolicy(
                max_age_ticks=int(decay_policy_raw["max_age_ticks"]),
                half_life_ticks=(
                    int(decay_policy_raw["half_life_ticks"])
                    if decay_policy_raw.get("half_life_ticks") is not None
                    else None
                ),
            )
        min_attestation_trust_level_raw = source.get("min_attestation_trust_level")
        min_attestation_trust_level: str | None = None
        if min_attestation_trust_level_raw is not None:
            min_attestation_trust_level = str(min_attestation_trust_level_raw).strip().lower()
            if min_attestation_trust_level not in ATTESTATION_TRUST_LEVELS:
                raise ValueError(
                    "min_attestation_trust_level must be one of "
                    f"{list(ATTESTATION_TRUST_LEVELS)} when provided"
                )
        allowed_attestation_issuers_raw = source.get("allowed_attestation_issuers")
        allowed_attestation_issuers: frozenset[str] = frozenset()
        if allowed_attestation_issuers_raw is not None:
            if isinstance(allowed_attestation_issuers_raw, (str, bytes)) or not isinstance(
                allowed_attestation_issuers_raw, list
            ):
                raise ValueError("allowed_attestation_issuers must be a JSON array when provided")
            normalized_issuers: list[str] = []
            for issuer in allowed_attestation_issuers_raw:
                issuer_text = str(issuer).strip()
                if not issuer_text:
                    raise ValueError("allowed_attestation_issuers entries must be non-empty strings")
                normalized_issuers.append(issuer_text)
            allowed_attestation_issuers = frozenset(normalized_issuers)
        tenant_id = trusted.get("tenant_id")
        if tenant_id is None:
            tenant_id = source.get("tenant_id")
        uncertainty_score = source.get("uncertainty_score")
        if uncertainty_score is not None:
            uncertainty_score = float(uncertainty_score)
        uncertainty_threshold = source.get("uncertainty_threshold")
        if uncertainty_threshold is not None:
            uncertainty_threshold = float(uncertainty_threshold)
        uncertainty_reason = source.get("uncertainty_reason")
        if uncertainty_reason is not None:
            uncertainty_reason = str(uncertainty_reason)
        return PolicyContext(
            role=str(trusted.get("role", "runtime")),
            capabilities=frozenset(trusted.get("capabilities", [])),
            allow_overrides=bool(trusted.get("allow_overrides", False)),
            tenant_id=(str(tenant_id) if tenant_id is not None else None),
            trusted_subject=trusted_context is not None,
            current_tick=(
                int(source["current_tick"]) if source.get("current_tick") is not None else None
            ),
            decay_policy=decay_policy,
            require_attestation=bool(source.get("require_attestation", False)),
            min_attestation_trust_level=min_attestation_trust_level,
            allowed_attestation_issuers=allowed_attestation_issuers,
            uncertainty_score=uncertainty_score,
            uncertainty_threshold=uncertainty_threshold,
            uncertainty_reason=uncertainty_reason,
            allow_low_uncertainty_override=bool(
                source.get("allow_low_uncertainty_override", False)
            ),
        )

    def _expected_tenant_id(self, trusted_context: Mapping[str, Any] | None = None) -> str | None:
        if trusted_context is None:
            return None
        tenant_id = trusted_context.get("tenant_id")
        if tenant_id is None:
            return None
        tenant_id_str = str(tenant_id).strip()
        if not tenant_id_str:
            raise ValueError("trusted_context.tenant_id must be non-empty when provided")
        return tenant_id_str

    def _invalidate_read_model_cache(self) -> None:
        self._state_cache = None
        self._events_cache = None
        if self.query_backend_name == "inmemory":
            self._query_index_cache = None

    def _next_sequence(self) -> int:
        return len(self.log) + 1

    def _normalize_timestamp(
        self,
        timestamp: Mapping[str, Any] | None,
        *,
        sequence: int,
    ) -> dict[str, Any]:
        if timestamp is None:
            wall_time = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
            return {"wall_time": wall_time, "tick": sequence}
        out = dict(timestamp)
        out.setdefault("tick", sequence)
        return out

    def _validate_dynamic_event(self, event: EventEnvelope) -> None:
        if event.event_type not in {
            "recalled",
            "reconsolidated",
            "promoted",
            "linked",
            "reinforced",
            "conflicted",
            "merge_proposed",
            "merge_approved",
            "merge_rejected",
        }:
            return
        if event.event_type == "promoted":
            if self.state_map().get(event.memory_id) is not None:
                raise ValueError("promoted events must create a new semantic memory")
            if (
                len(event.promoted_from_memory_ids) == 0
                or len(event.promoted_from_memory_ids) != len(event.promoted_from_event_ids)
            ):
                raise ValueError(
                    "promoted events require aligned promoted_from_memory_ids and promoted_from_event_ids"
                )
            if tuple(event.previous_events) != tuple(event.promoted_from_event_ids):
                raise ValueError("promoted events must point to the source head events")
            for source_memory_id, source_event_id in zip(
                event.promoted_from_memory_ids,
                event.promoted_from_event_ids,
            ):
                state = self.state_map().get(source_memory_id)
                if state is None:
                    raise ValueError("promoted events require existing source memories")
                if state.tenant_id != event.tenant_id:
                    raise ValueError("promoted events must stay within a single tenant")
                if state.last_event_id != source_event_id:
                    raise ValueError("promoted events must reference current source heads")
                if state.memory_class != "episodic":
                    raise ValueError("promoted events may only derive from episodic memories")
            return
        if event.event_type == "merge_proposed":
            if self.state_map().get(event.memory_id) is not None:
                raise ValueError("merge_proposed events must create a new semantic memory")
            if (
                len(event.resolved_from_memory_ids) < 2
                or len(event.resolved_from_memory_ids) != len(event.resolved_from_event_ids)
            ):
                raise ValueError(
                    "merge_proposed events require aligned resolved_from_memory_ids and resolved_from_event_ids"
                )
            if tuple(event.previous_events) != tuple(event.resolved_from_event_ids):
                raise ValueError("merge_proposed events must point to the source head events")
            for source_memory_id, source_event_id in zip(
                event.resolved_from_memory_ids,
                event.resolved_from_event_ids,
            ):
                source_state = self.state_map().get(source_memory_id)
                if source_state is None:
                    raise ValueError("merge_proposed events require existing source memories")
                if source_state.tenant_id != event.tenant_id:
                    raise ValueError("merge_proposed events must stay within a single tenant")
                if source_state.last_event_id != source_event_id:
                    raise ValueError("merge_proposed events must reference current source heads")
            return
        state = self.state_map().get(event.memory_id)
        if state is None:
            raise ValueError(f"{event.event_type} events require an existing memory head")
        if tuple(event.previous_events) != (state.last_event_id,):
            raise ValueError(
                f"{event.event_type} events must point to the current memory head"
            )
        if event.event_type in {"merge_approved", "merge_rejected"}:
            if state.last_event_type != "merge_proposed":
                raise ValueError(f"{event.event_type} events require an open merge proposal")
            if event.payload_hash != state.payload_hash:
                raise ValueError(f"{event.event_type} events must preserve the current payload_hash")
            return
        if event.event_type in {"linked", "reinforced", "conflicted"}:
            if event.payload_hash != state.payload_hash:
                raise ValueError(
                    f"{event.event_type} events must preserve the current payload_hash"
                )
            if event.target_memory_id is not None:
                target_state = self.state_map().get(event.target_memory_id)
                if target_state is None:
                    raise ValueError(f"{event.event_type} events require an existing target memory")
                if target_state.tenant_id != state.tenant_id:
                    raise ValueError(f"{event.event_type} events must stay within a single tenant")
            return
        if event.event_type == "recalled":
            if event.trust_transition is not None:
                raise ValueError("recalled events must not include trust_transition")
            if event.payload_hash != state.payload_hash:
                raise ValueError("recalled events must preserve the current payload_hash")
            return
        if event.payload_hash == state.payload_hash:
            raise ValueError(
                "reconsolidated events must change the payload_hash from the current head"
            )

    def _policy_outcome(
        self,
        memory_id: str,
        *,
        policy_context: Mapping[str, Any] | None = None,
        trusted_context: Mapping[str, Any] | None = None,
    ) -> tuple[PolicyContext, Any]:
        ctx = self._build_policy_context(policy_context, trusted_context=trusted_context)
        outcome = get_outcome(memory_id, self.state_map(), ctx)
        return ctx, outcome

    def _mutation_result(
        self,
        *,
        outcome: str,
        record: dict[str, Any] | None = None,
        denial_reason: str | None = None,
        event: EventEnvelope | None = None,
    ) -> dict[str, Any]:
        result: dict[str, Any] = {
            "outcome": outcome,
            "record": record,
            "denial_reason": denial_reason,
        }
        if event is not None:
            result["event"] = event.to_dict()
        return result

    def _peek_record(
        self,
        memory_id: str,
        *,
        policy_context: Mapping[str, Any] | None = None,
        trusted_context: Mapping[str, Any] | None = None,
    ) -> dict[str, Any] | None:
        ctx = self._build_policy_context(policy_context, trusted_context=trusted_context)
        outcome = get_outcome(memory_id, self.state_map(), ctx)
        return None if outcome.record is None else outcome.record.__dict__

    def _assess_promotion_state(
        self,
        memory_id: str,
        *,
        policy_context: Mapping[str, Any] | None = None,
        trusted_context: Mapping[str, Any] | None = None,
    ) -> tuple[PolicyContext, PromotionAssessment]:
        ctx = self._build_policy_context(policy_context, trusted_context=trusted_context)
        state = self.state_map().get(memory_id)
        if state is None:
            return ctx, PromotionAssessment(
                memory_id=memory_id,
                tenant_id=ctx.tenant_id,
                memory_class=None,
                source_event_id=None,
                promotion_score=None,
                promotion_eligible=False,
                denial_reason="memory_not_found",
                override_used=False,
                promoted_from_memory_ids=(),
            )

        outcome = get_outcome(memory_id, self.state_map(), ctx)
        override_used = False if outcome.record is None else outcome.record.override_used
        denial_reason = outcome.denial_reason if outcome.record is None else None
        if denial_reason is None:
            if state.memory_class != "episodic":
                denial_reason = "memory_class_not_promotable"
            elif not state.queryable_payload_present:
                denial_reason = "queryable_payload_required_for_promotion"
        return ctx, PromotionAssessment(
            memory_id=memory_id,
            tenant_id=state.tenant_id,
            memory_class=state.memory_class,
            source_event_id=state.last_event_id,
            promotion_score=compute_promotion_score(
                state,
                current_tick=ctx.current_tick,
                decay_policy=ctx.decay_policy,
            ),
            promotion_eligible=denial_reason is None,
            denial_reason=denial_reason,
            override_used=override_used,
            promoted_from_memory_ids=state.promoted_from_memory_ids,
        )

    def _has_conflict_relationship(
        self,
        left_memory_id: str,
        right_memory_id: str,
        state_map: Mapping[str, MemoryState],
    ) -> bool:
        left = state_map.get(left_memory_id)
        right = state_map.get(right_memory_id)
        if left is None or right is None:
            return False
        return (
            right_memory_id in left.conflicted_memory_ids
            or left_memory_id in right.conflicted_memory_ids
        )

    def _assess_conflict_state(
        self,
        memory_id: str,
        related_memory_id: str,
        *,
        policy_context: Mapping[str, Any] | None = None,
        trusted_context: Mapping[str, Any] | None = None,
    ) -> tuple[PolicyContext, ConflictAssessment]:
        ctx = self._build_policy_context(policy_context, trusted_context=trusted_context)
        state_map = self.state_map()
        left = state_map.get(memory_id)
        right = state_map.get(related_memory_id)
        if left is None:
            return ctx, ConflictAssessment(
                memory_id=memory_id,
                related_memory_id=related_memory_id,
                tenant_id=ctx.tenant_id,
                source_event_ids=(),
                conflict_set_id=None,
                resolvable=False,
                denial_reason="memory_not_found",
                override_used=False,
            )
        if right is None:
            return ctx, ConflictAssessment(
                memory_id=memory_id,
                related_memory_id=related_memory_id,
                tenant_id=left.tenant_id,
                source_event_ids=(left.last_event_id,),
                conflict_set_id=None,
                resolvable=False,
                denial_reason="related_memory_not_found",
                override_used=False,
            )
        if memory_id == related_memory_id:
            return ctx, ConflictAssessment(
                memory_id=memory_id,
                related_memory_id=related_memory_id,
                tenant_id=left.tenant_id,
                source_event_ids=(left.last_event_id, right.last_event_id),
                conflict_set_id=None,
                resolvable=False,
                denial_reason="same_memory_not_allowed",
                override_used=False,
            )
        if left.tenant_id != right.tenant_id:
            return ctx, ConflictAssessment(
                memory_id=memory_id,
                related_memory_id=related_memory_id,
                tenant_id=left.tenant_id,
                source_event_ids=(left.last_event_id, right.last_event_id),
                conflict_set_id=None,
                resolvable=False,
                denial_reason="cross_tenant_merge_default_deny",
                override_used=False,
            )
        left_outcome = get_outcome(memory_id, state_map, ctx)
        right_outcome = get_outcome(related_memory_id, state_map, ctx)
        if left_outcome.record is None:
            return ctx, ConflictAssessment(
                memory_id=memory_id,
                related_memory_id=related_memory_id,
                tenant_id=left.tenant_id,
                source_event_ids=(left.last_event_id, right.last_event_id),
                conflict_set_id=None,
                resolvable=False,
                denial_reason=left_outcome.denial_reason,
                override_used=False,
            )
        if right_outcome.record is None:
            return ctx, ConflictAssessment(
                memory_id=memory_id,
                related_memory_id=related_memory_id,
                tenant_id=left.tenant_id,
                source_event_ids=(left.last_event_id, right.last_event_id),
                conflict_set_id=None,
                resolvable=False,
                denial_reason=right_outcome.denial_reason,
                override_used=left_outcome.record.override_used,
            )
        if not left.queryable_payload_present or not right.queryable_payload_present:
            return ctx, ConflictAssessment(
                memory_id=memory_id,
                related_memory_id=related_memory_id,
                tenant_id=left.tenant_id,
                source_event_ids=(left.last_event_id, right.last_event_id),
                conflict_set_id=None,
                resolvable=False,
                denial_reason="queryable_payload_required_for_merge",
                override_used=(
                    left_outcome.record.override_used or right_outcome.record.override_used
                ),
            )
        if not self._has_conflict_relationship(memory_id, related_memory_id, state_map):
            return ctx, ConflictAssessment(
                memory_id=memory_id,
                related_memory_id=related_memory_id,
                tenant_id=left.tenant_id,
                source_event_ids=(left.last_event_id, right.last_event_id),
                conflict_set_id=None,
                resolvable=False,
                denial_reason="conflict_edge_required",
                override_used=(
                    left_outcome.record.override_used or right_outcome.record.override_used
                ),
            )
        return ctx, ConflictAssessment(
            memory_id=memory_id,
            related_memory_id=related_memory_id,
            tenant_id=left.tenant_id,
            source_event_ids=(left.last_event_id, right.last_event_id),
            conflict_set_id=stable_conflict_set_id((memory_id, related_memory_id)),
            resolvable=True,
            denial_reason=None,
            override_used=left_outcome.record.override_used or right_outcome.record.override_used,
        )

    def _append_dynamic_event(
        self,
        *,
        memory_id: str,
        event_type: str,
        actor: Mapping[str, Any] | Actor,
        payload_hash: str,
        payload: Any | None = None,
        trusted_context: Mapping[str, Any] | None,
        event_id: str | None = None,
        timestamp: Mapping[str, Any] | None = None,
        evidence_refs: list[Mapping[str, Any]] | None = None,
        signature: Mapping[str, Any] | None = None,
        attestation: Mapping[str, Any] | None = None,
        target_memory_id: str | None = None,
        edge_weight: float | None = None,
        edge_reason: str | None = None,
        resolution_reason: str | None = None,
    ) -> EventEnvelope:
        state = self.state_map().get(memory_id)
        if state is None:
            raise ValueError(f"{event_type} events require an existing memory head")
        sequence = self._next_sequence()
        actor_dict = actor.to_dict() if isinstance(actor, Actor) else dict(actor)
        event_data: dict[str, Any] = {
            "event_id": event_id or str(uuid4()),
            "sequence": sequence,
            "timestamp": self._normalize_timestamp(timestamp, sequence=sequence),
            "actor": actor_dict,
            "tenant_id": state.tenant_id,
            "memory_id": memory_id,
            "event_type": event_type,
            "previous_events": [state.last_event_id],
            "payload_hash": payload_hash,
        }
        if payload is not None:
            event_data["payload"] = payload
        if target_memory_id is not None:
            event_data["target_memory_id"] = target_memory_id
        if edge_weight is not None:
            event_data["edge_weight"] = edge_weight
        if edge_reason is not None:
            event_data["edge_reason"] = edge_reason
        if resolution_reason is not None:
            event_data["resolution_reason"] = resolution_reason
        if evidence_refs is not None:
            event_data["evidence_refs"] = evidence_refs
        if signature is not None:
            event_data["signature"] = signature
        if attestation is not None:
            event_data["attestation"] = attestation
        return self.ingest_event(
            event_data,
            expected_tenant_id=self._expected_tenant_id(trusted_context),
            trusted_context=trusted_context,
        )

    def _load_events_and_signature_states(self) -> tuple[tuple[EventEnvelope, ...], dict[str, str]]:
        if hasattr(self.log, "all_events_with_signature_states"):
            events, signature_states = self.log.all_events_with_signature_states()
            self._events_cache = events
            return events, signature_states
        if self._events_cache is None:
            self._events_cache = self.log.all_events()
        return self._events_cache, self.log.signature_states()

    def _load_all_events_cached(self) -> tuple[EventEnvelope, ...]:
        if self._events_cache is None:
            self._events_cache = self.log.all_events()
        return self._events_cache

    def _emit_audit(self, event: dict[str, Any]) -> None:
        if self.audit_sink is None:
            return
        self.audit_sink(dict(event))

    def _query_index(self) -> QueryBackend:
        if self._query_index_cache is None:
            self._query_index_cache = InMemoryQueryIndex.build(self.state_map())
        return self._query_index_cache

    def _query_backend_memory_class(
        self,
        structured_filter: Mapping[str, Any] | None,
    ) -> str | None:
        if structured_filter is None:
            return None
        memory_class = structured_filter.get("memory_class")
        if memory_class is None:
            return None
        return str(memory_class)

    def _refresh_query_backend(
        self,
        *,
        memory_ids: tuple[str, ...] | None = None,
    ) -> None:
        if self.query_backend_name != "pgvector":
            return
        backend = self._query_index()
        try:
            backend.refresh(self.state_map(), memory_ids=memory_ids)
        except QueryBackendError:
            raise
        except Exception as exc:  # pragma: no cover - defensive boundary
            raise QueryBackendError(f"semantic query backend refresh failed: {exc}") from exc

    def _query_sync_mode(self) -> str:
        if self.query_backend_name != "pgvector":
            return "not_applicable"
        if isinstance(self.log, PostgresEventLog):
            return "durable_outbox"
        return "direct_refresh"

    def _query_sync_tasks_for_event(
        self,
        event: EventEnvelope,
        *,
        pre_state_map: Mapping[str, MemoryState] | None = None,
    ) -> tuple[QuerySyncTask, ...]:
        tasks: list[QuerySyncTask] = [
            QuerySyncTask(
                tenant_id=event.tenant_id,
                memory_id=event.memory_id,
                indexed_event_id=event.event_id,
                reason=event.event_type,
            )
        ]
        state_map = pre_state_map if pre_state_map is not None else self.state_map()
        if event.event_type == "merge_approved":
            proposal_state = state_map.get(event.memory_id)
            if proposal_state is not None:
                for source_memory_id in proposal_state.resolved_from_memory_ids:
                    source_state = state_map.get(source_memory_id)
                    if source_state is None:
                        continue
                    tasks.append(
                        QuerySyncTask(
                            tenant_id=source_state.tenant_id,
                            memory_id=source_state.memory_id,
                            indexed_event_id=source_state.last_event_id,
                            reason="merge_approved_source_state",
                        )
                    )
        deduped: dict[tuple[str, str], QuerySyncTask] = {}
        for task in tasks:
            deduped[(task.tenant_id, task.memory_id)] = task
        return tuple(deduped.values())

    def sync_query_index(
        self,
        *,
        full_refresh: bool = False,
        limit: int | None = None,
        memory_ids: tuple[str, ...] | None = None,
    ) -> int:
        if self.query_backend_name != "pgvector":
            return 0
        if limit is not None and limit < 1:
            raise ValueError("limit must be >= 1 when provided")
        state_map = self.state_map()
        sync_mode = self._query_sync_mode()
        processed = 0
        backend = self._query_index()
        if isinstance(self.log, PostgresEventLog) and not full_refresh and memory_ids is None:
            pending = self.log.pending_query_sync(limit=limit)
            if pending:
                try:
                    backend.refresh(
                        state_map,
                        memory_ids=tuple(dict.fromkeys(item.memory_id for item in pending)),
                    )
                    self.log.mark_query_sync_processed(tuple(item.id for item in pending))
                except QueryBackendError as exc:
                    raise QuerySyncError(str(exc)) from exc
                except PostgresBackendError as exc:
                    raise QuerySyncError(str(exc)) from exc
                processed = len(pending)
        else:
            try:
                backend.refresh(state_map, memory_ids=memory_ids if not full_refresh else None)
            except QueryBackendError as exc:
                raise QuerySyncError(str(exc)) from exc
            if isinstance(self.log, PostgresEventLog):
                pending = self.log.pending_query_sync(limit=limit)
                if full_refresh:
                    matching_ids = tuple(item.id for item in pending)
                elif memory_ids is not None:
                    memory_id_set = set(memory_ids)
                    matching_ids = tuple(
                        item.id for item in pending if item.memory_id in memory_id_set
                    )
                else:
                    matching_ids = ()
                self.log.mark_query_sync_processed(matching_ids)
                processed = len(matching_ids)
            else:
                processed = (
                    len(memory_ids) if memory_ids is not None and not full_refresh else len(state_map)
                )
        self._emit_audit(
            {
                "type": "memory.query_sync",
                "query_sync_mode": sync_mode,
                "outbox_rows_processed": processed,
            }
        )
        return processed

    def sync_query_backend(
        self,
        *,
        full_refresh: bool = False,
        limit: int | None = None,
        memory_ids: tuple[str, ...] | None = None,
    ) -> int:
        return self.sync_query_index(full_refresh=full_refresh, limit=limit, memory_ids=memory_ids)

    def _reference_tick(self, state_map: Mapping[str, MemoryState]) -> int:
        if not state_map:
            return 0
        return max(state.last_tick for state in state_map.values())

    def _normalize_graph_edge_kinds(
        self,
        graph_edge_kinds: list[str] | tuple[str, ...] | set[str] | None,
    ) -> tuple[str, ...]:
        if graph_edge_kinds is None:
            return tuple(sorted(GRAPH_EXPANDABLE_EDGE_KINDS))
        normalized: list[str] = []
        for item in graph_edge_kinds:
            edge_kind = str(item).strip().lower()
            if edge_kind not in {"linked", "reinforced", "conflicted"}:
                raise ValueError("graph_edge_kinds entries must be linked, reinforced, or conflicted")
            if edge_kind not in normalized:
                normalized.append(edge_kind)
        return tuple(normalized)

    def _matches_structured_filter(
        self,
        state: MemoryState,
        structured_filter: Mapping[str, Any] | None,
    ) -> bool:
        if structured_filter is None:
            return True
        allowed_fields = {
            "memory_id",
            "tenant_id",
            "memory_class",
            "trust_state",
            "lifecycle_state",
            "signature_state",
            "version",
            "queryable_payload_present",
            "promotion_eligible",
            "conflict_open",
            "merged_into_memory_id",
            "superseded_by_memory_id",
            "min_reinforcement_score",
            "max_conflict_score",
        }
        for key, expected in structured_filter.items():
            if key not in allowed_fields:
                raise ValueError(f"unsupported structured_filter field: {key}")
            if key == "min_reinforcement_score":
                if state.reinforcement_score < float(expected):
                    return False
                continue
            if key == "max_conflict_score":
                if state.conflict_score > float(expected):
                    return False
                continue
            if getattr(state, key) != expected:
                return False
        return True

    def _query_candidate_record(
        self,
        candidate: QueryCandidate,
        *,
        state_map: dict[str, MemoryState],
        ctx: PolicyContext,
        trust_states: set[str] | None,
        structured_filter: Mapping[str, Any] | None,
    ) -> tuple[dict[str, Any] | None, str | None, bool]:
        state = state_map.get(candidate.memory_id)
        if state is None:
            return None, None, False
        if state.last_event_id != candidate.indexed_event_id:
            return None, None, False
        if trust_states is not None and state.trust_state not in trust_states:
            return None, "__trust_state_filtered__", False
        if not self._matches_structured_filter(state, structured_filter):
            return None, "__structured_filtered__", False
        outcome = get_outcome(candidate.memory_id, state_map, ctx)
        if outcome.record is None:
            return None, outcome.denial_reason or "policy_denied", False
        decision_record = to_retrieval_record(
            state,
            why_sound=outcome.record.why_sound,
            denial_reason=outcome.record.denial_reason,
            override_used=outcome.record.override_used,
            retrieval_score=candidate.retrieval_score,
            retrieval_mode=candidate.retrieval_mode,
            indexed_event_id=candidate.indexed_event_id,
        )
        return decision_record.__dict__, None, decision_record.override_used

    def state_map(self) -> dict[str, MemoryState]:
        if self._state_cache is None:
            events, signature_states = self._load_events_and_signature_states()
            self._state_cache = replay_events(events, signature_states=signature_states)
        return dict(self._state_cache)

    def ingest_event(
        self,
        event_data: Mapping[str, Any],
        *,
        expected_tenant_id: str | None = None,
        trusted_context: Mapping[str, Any] | None = None,
    ) -> EventEnvelope:
        event = EventEnvelope.from_dict(event_data)
        expected_tenant_id = expected_tenant_id or self._expected_tenant_id(trusted_context)
        if expected_tenant_id is not None and event.tenant_id != expected_tenant_id:
            raise ValueError("tenant mismatch between trusted context and event payload")
        pre_state_map = self.state_map()
        self._validate_dynamic_event(event)
        query_sync_tasks = self._query_sync_tasks_for_event(event, pre_state_map=pre_state_map)
        self.log.append(
            event,
            signature_verifier=self._signature_verifier,
            query_sync_tasks=query_sync_tasks,
        )
        self._invalidate_read_model_cache()
        self.sync_query_index(memory_ids=tuple(task.memory_id for task in query_sync_tasks))
        return event

    def import_records(
        self,
        records: list[Mapping[str, Any]],
        *,
        actor: Mapping[str, Any],
        default_timestamp: str,
        start_sequence: int | None = None,
        default_tick: int | None = None,
        tenant_id: str | None = None,
        expected_tenant_id: str | None = None,
        trusted_context: Mapping[str, Any] | None = None,
    ) -> tuple[EventEnvelope, ...]:
        expected_tenant_id = expected_tenant_id or self._expected_tenant_id(trusted_context)
        effective_tenant_id = tenant_id
        if expected_tenant_id is not None:
            if effective_tenant_id is not None and effective_tenant_id != expected_tenant_id:
                raise ValueError("tenant mismatch between trusted context and import request")
            effective_tenant_id = expected_tenant_id
        if effective_tenant_id is None:
            raise ValueError("tenant_id is required for import_records")
        if start_sequence is None:
            start_sequence = len(self.log) + 1
        events = append_imported_records(
            self.log,
            records,
            actor=actor,
            start_sequence=start_sequence,
            default_timestamp=default_timestamp,
            default_tick=default_tick,
            tenant_id=effective_tenant_id,
            signature_verifier=self._signature_verifier,
            query_sync_task_builder=self._query_sync_tasks_for_event,
        )
        self._invalidate_read_model_cache()
        self.sync_query_index(
            memory_ids=tuple(dict.fromkeys(event.memory_id for event in events))
        )
        return events

    def query(
        self,
        *,
        policy_context: Mapping[str, Any] | None = None,
        trusted_context: Mapping[str, Any] | None = None,
        query_text: str | None = None,
        structured_filter: Mapping[str, Any] | None = None,
        trust_states: set[str] | None = None,
        limit: int | None = None,
        graph_expand: bool = False,
        graph_edge_kinds: list[str] | tuple[str, ...] | set[str] | None = None,
    ) -> dict[str, Any]:
        ctx = self._build_policy_context(policy_context, trusted_context=trusted_context)
        semantic_query = bool(query_text and str(query_text).strip())
        backend_name = self._query_index().name if semantic_query else None
        query_sync_mode = self._query_sync_mode()
        query_sync_lag_count = (
            self.log.query_sync_lag_count() if semantic_query and query_sync_mode == "durable_outbox" else None
        )
        gate = evaluate_query_gate(ctx)
        if not gate.allowed:
            denied = {
                "count": 0,
                "records": [],
                "query_allowed": False,
                "query_denial_reason": gate.denial_reason,
                "query_override_used": gate.override_used,
            }
            if semantic_query:
                denied.update(
                    {
                        "query_backend": backend_name,
                        "candidate_count": 0,
                        "stale_index_filtered": 0,
                    }
                )
            self._emit_audit(
                {
                    "type": "memory.query",
                    "tenant_id": ctx.tenant_id,
                    "limit": limit,
                    "trust_states": sorted(trust_states) if trust_states is not None else None,
                    "considered": 0,
                    "allowed": 0,
                    "trust_state_filtered": 0,
                    "override_used_count": 0,
                    "denied_by_reason": {},
                    "query_allowed": False,
                    "query_denial_reason": gate.denial_reason,
                    "query_override_used": gate.override_used,
                    "uncertainty_score": ctx.uncertainty_score,
                    "uncertainty_threshold": ctx.uncertainty_threshold,
                    "query_text_present": semantic_query,
                    "query_backend": backend_name,
                    "candidate_count": 0,
                    "stale_index_filtered": 0,
                    "backend_latency_ms": None,
                    "query_sync_mode": query_sync_mode,
                    "query_sync_lag_count": query_sync_lag_count,
                }
            )
            return denied
        state_map = self.state_map()
        if structured_filter is not None and not isinstance(structured_filter, Mapping):
            raise ValueError("structured_filter must be an object when provided")
        requested_graph_edge_kinds = self._normalize_graph_edge_kinds(graph_edge_kinds)
        backend_latency_ms: float | None = None
        candidate_count: int | None = None
        stale_index_filtered: int | None = None
        if query_text is None or not str(query_text).strip():
            if structured_filter is None:
                records, summary = query_with_summary(
                    state_map,
                    ctx,
                    trust_states=trust_states,
                    limit=limit,
                )
            else:
                records = []
                considered = 0
                trust_state_filtered = 0
                override_used_count = 0
                denied_by_reason: dict[str, int] = {}
                for state in sorted(
                    state_map.values(), key=lambda item: item.last_sequence, reverse=True
                ):
                    considered += 1
                    if trust_states is not None and state.trust_state not in trust_states:
                        trust_state_filtered += 1
                        continue
                    if not self._matches_structured_filter(state, structured_filter):
                        continue
                    outcome = get_outcome(state.memory_id, state_map, ctx)
                    if outcome.record is None:
                        reason = outcome.denial_reason or "policy_denied"
                        denied_by_reason[reason] = denied_by_reason.get(reason, 0) + 1
                        continue
                    if outcome.record.override_used:
                        override_used_count += 1
                    records.append(outcome.record)
                    if limit is not None and len(records) >= limit:
                        break
                from .retrieval import QueryAuditSummary  # local import to avoid cycle

                summary = QueryAuditSummary(
                    considered=considered,
                    allowed=len(records),
                    trust_state_filtered=trust_state_filtered,
                    override_used_count=override_used_count,
                    denied_by_reason=denied_by_reason,
                )
            records_out = [record.__dict__ for record in records]
        else:
            reference_tick = self._reference_tick(state_map)
            considered = 0
            trust_state_filtered = 0
            override_used_count = 0
            denied_by_reason: dict[str, int] = {}
            records_out: list[dict[str, Any]] = []
            stale_index_filtered = 0
            search_started = time.perf_counter()
            try:
                hits = self._query_index().search(
                    query_text=str(query_text),
                    tenant_id=ctx.tenant_id,
                    memory_class=self._query_backend_memory_class(structured_filter),
                    limit=None,
                )
            except QueryBackendError:
                raise
            except Exception as exc:  # pragma: no cover - defensive boundary
                raise QueryBackendError(f"semantic query backend search failed: {exc}") from exc
            backend_latency_ms = round((time.perf_counter() - search_started) * 1000.0, 3)
            candidate_count = len(hits)
            candidates: dict[str, QueryCandidate] = {}
            direct_memory_ids: list[str] = []
            for hit in hits:
                state = state_map.get(hit.memory_id)
                if state is None:
                    stale_index_filtered += 1
                    continue
                if state.last_event_id != hit.indexed_event_id:
                    stale_index_filtered += 1
                    continue
                score = direct_retrieval_score(
                    lexical_score=hit.retrieval_score,
                    state=state,
                    reference_tick=reference_tick,
                )
                candidates[hit.memory_id] = QueryCandidate(
                    memory_id=hit.memory_id,
                    retrieval_score=score,
                    retrieval_mode="lexical_graph_v1" if graph_expand else hit.retrieval_mode,
                    indexed_event_id=hit.indexed_event_id,
                    expanded_rank=0,
                )
                direct_memory_ids.append(hit.memory_id)
            if graph_expand:
                for source_memory_id in direct_memory_ids:
                    source_candidate = candidates[source_memory_id]
                    source_state = state_map.get(source_memory_id)
                    if source_state is None:
                        continue
                    for target_memory_id, edge_kind in source_state.relationship_edges:
                        if edge_kind not in requested_graph_edge_kinds:
                            continue
                        target_state = state_map.get(target_memory_id)
                        if target_state is None:
                            continue
                        expanded = QueryCandidate(
                            memory_id=target_memory_id,
                            retrieval_score=expanded_retrieval_score(
                                source_score=source_candidate.retrieval_score,
                                target_state=target_state,
                                edge_kind=edge_kind,
                                edge_weight=None,
                                reference_tick=reference_tick,
                            ),
                            retrieval_mode="graph_expand_v1",
                            indexed_event_id=target_state.last_event_id,
                            expanded_rank=1,
                        )
                        existing = candidates.get(target_memory_id)
                        if existing is None or (
                            existing.expanded_rank > expanded.expanded_rank
                            or (
                                existing.expanded_rank == expanded.expanded_rank
                                and existing.retrieval_score < expanded.retrieval_score
                            )
                        ):
                            candidates[target_memory_id] = expanded
            sorted_candidates = sorted(
                candidates.values(),
                key=lambda item: (
                    item.expanded_rank,
                    -item.retrieval_score,
                    item.memory_id,
                    item.indexed_event_id,
                ),
            )
            for candidate in sorted_candidates:
                considered += 1
                record, reason, override_used = self._query_candidate_record(
                    candidate,
                    state_map=state_map,
                    ctx=ctx,
                    trust_states=trust_states,
                    structured_filter=structured_filter,
                )
                if reason == "__trust_state_filtered__":
                    trust_state_filtered += 1
                    continue
                if reason == "__structured_filtered__":
                    continue
                if record is None:
                    if reason is not None:
                        denied_by_reason[reason] = denied_by_reason.get(reason, 0) + 1
                    continue
                if override_used:
                    override_used_count += 1
                records_out.append(record)
                if limit is not None and len(records_out) >= limit:
                    break
            from .retrieval import QueryAuditSummary  # local import to avoid cycle

            summary = QueryAuditSummary(
                considered=considered,
                allowed=len(records_out),
                trust_state_filtered=trust_state_filtered,
                override_used_count=override_used_count,
                denied_by_reason=denied_by_reason,
            )
        response = {
            "count": len(records_out),
            "records": records_out,
            "query_allowed": True,
            "query_denial_reason": gate.denial_reason,
            "query_override_used": gate.override_used,
        }
        if semantic_query:
            response.update(
                {
                    "query_backend": backend_name,
                    "candidate_count": candidate_count if candidate_count is not None else 0,
                    "stale_index_filtered": (
                        stale_index_filtered if stale_index_filtered is not None else 0
                    ),
                }
            )
        self._emit_audit(
            {
                "type": "memory.query",
                "tenant_id": ctx.tenant_id,
                "limit": limit,
                "trust_states": sorted(trust_states) if trust_states is not None else None,
                "considered": summary.considered,
                "allowed": summary.allowed,
                "trust_state_filtered": summary.trust_state_filtered,
                "override_used_count": summary.override_used_count,
                "denied_by_reason": dict(summary.denied_by_reason),
                "query_text_present": semantic_query,
                "graph_expand": graph_expand,
                "graph_edge_kinds": list(requested_graph_edge_kinds) if graph_expand else [],
                "query_allowed": True,
                "query_denial_reason": gate.denial_reason,
                "query_override_used": gate.override_used,
                "uncertainty_score": ctx.uncertainty_score,
                "uncertainty_threshold": ctx.uncertainty_threshold,
                "query_backend": backend_name,
                "candidate_count": candidate_count if semantic_query else None,
                "stale_index_filtered": stale_index_filtered if semantic_query else None,
                "backend_latency_ms": backend_latency_ms if semantic_query else None,
                "query_sync_mode": query_sync_mode,
                "query_sync_lag_count": query_sync_lag_count,
            }
        )
        return response

    def peek(
        self,
        memory_id: str,
        *,
        policy_context: Mapping[str, Any] | None = None,
        trusted_context: Mapping[str, Any] | None = None,
        audit_type: str = "memory.peek",
    ) -> dict[str, Any] | None:
        ctx = self._build_policy_context(policy_context, trusted_context=trusted_context)
        outcome = get_outcome(memory_id, self.state_map(), ctx)
        self._emit_audit(
            {
                "type": audit_type,
                "tenant_id": ctx.tenant_id,
                "memory_id": memory_id,
                "outcome": outcome.outcome,
                "denial_reason": outcome.denial_reason,
            }
        )
        return None if outcome.record is None else outcome.record.__dict__

    def get(
        self,
        memory_id: str,
        *,
        policy_context: Mapping[str, Any] | None = None,
        trusted_context: Mapping[str, Any] | None = None,
    ) -> dict[str, Any] | None:
        return self.peek(
            memory_id,
            policy_context=policy_context,
            trusted_context=trusted_context,
            audit_type="memory.get",
        )

    def assess_promotion(
        self,
        memory_id: str,
        *,
        policy_context: Mapping[str, Any] | None = None,
        trusted_context: Mapping[str, Any] | None = None,
    ) -> dict[str, Any]:
        ctx, assessment = self._assess_promotion_state(
            memory_id,
            policy_context=policy_context,
            trusted_context=trusted_context,
        )
        result = {
            "memory_id": assessment.memory_id,
            "tenant_id": assessment.tenant_id,
            "memory_class": assessment.memory_class,
            "source_event_id": assessment.source_event_id,
            "promotion_score": assessment.promotion_score,
            "promotion_eligible": assessment.promotion_eligible,
            "denial_reason": assessment.denial_reason,
            "override_used": assessment.override_used,
            "promoted_from_memory_ids": list(assessment.promoted_from_memory_ids),
        }
        self._emit_audit(
            {
                "type": "memory.assess_promotion",
                "tenant_id": ctx.tenant_id,
                "memory_id": memory_id,
                "promotion_score": assessment.promotion_score,
                "promotion_eligible": assessment.promotion_eligible,
                "denial_reason": assessment.denial_reason,
                "override_used": assessment.override_used,
            }
        )
        return result

    def assess_conflict(
        self,
        memory_id: str,
        related_memory_id: str,
        *,
        policy_context: Mapping[str, Any] | None = None,
        trusted_context: Mapping[str, Any] | None = None,
    ) -> dict[str, Any]:
        ctx, assessment = self._assess_conflict_state(
            memory_id,
            related_memory_id,
            policy_context=policy_context,
            trusted_context=trusted_context,
        )
        result = {
            "memory_id": assessment.memory_id,
            "related_memory_id": assessment.related_memory_id,
            "tenant_id": assessment.tenant_id,
            "source_event_ids": list(assessment.source_event_ids),
            "conflict_set_id": assessment.conflict_set_id,
            "resolvable": assessment.resolvable,
            "denial_reason": assessment.denial_reason,
            "override_used": assessment.override_used,
        }
        self._emit_audit(
            {
                "type": "memory.assess_conflict",
                "tenant_id": ctx.tenant_id,
                "memory_id": memory_id,
                "related_memory_id": related_memory_id,
                "conflict_set_id": assessment.conflict_set_id,
                "resolvable": assessment.resolvable,
                "denial_reason": assessment.denial_reason,
                "override_used": assessment.override_used,
            }
        )
        return result

    def promote(
        self,
        memory_ids: list[str] | tuple[str, ...],
        *,
        actor: Mapping[str, Any] | Actor,
        payload: Any,
        policy_context: Mapping[str, Any] | None = None,
        trusted_context: Mapping[str, Any] | None = None,
        promoted_memory_id: str | None = None,
        event_id: str | None = None,
        timestamp: Mapping[str, Any] | None = None,
        evidence_refs: list[Mapping[str, Any]] | None = None,
    ) -> dict[str, Any]:
        if not memory_ids:
            raise ValueError("memory_ids must include at least one source memory")
        if len({str(memory_id) for memory_id in memory_ids}) != len(memory_ids):
            raise ValueError("memory_ids must not contain duplicates")

        ctx = self._build_policy_context(policy_context, trusted_context=trusted_context)
        state_map = self.state_map()
        source_states: list[MemoryState] = []
        source_denials: dict[str, str] = {}
        for memory_id in memory_ids:
            _ctx, assessment = self._assess_promotion_state(
                memory_id,
                policy_context=policy_context,
                trusted_context=trusted_context,
            )
            if not assessment.promotion_eligible:
                source_denials[str(memory_id)] = assessment.denial_reason or "promotion_denied"
                continue
            state = state_map.get(str(memory_id))
            if state is None:
                source_denials[str(memory_id)] = "memory_not_found"
                continue
            source_states.append(state)
        if source_denials:
            denial_reason = next(iter(source_denials.values()))
            result = {
                "outcome": "denied",
                "record": None,
                "denial_reason": denial_reason,
                "source_denials": source_denials,
            }
            self._emit_audit(
                {
                    "type": "memory.promote",
                    "tenant_id": ctx.tenant_id,
                    "memory_ids": list(memory_ids),
                    "outcome": "denied",
                    "denial_reason": denial_reason,
                    "source_denials": dict(source_denials),
                }
            )
            return result

        tenant_ids = {state.tenant_id for state in source_states}
        if len(tenant_ids) != 1:
            raise ValueError("promotion sources must belong to a single tenant")
        new_memory_id = promoted_memory_id or str(uuid4())
        if new_memory_id in state_map:
            raise ValueError("promoted_memory_id already exists")
        sequence = self._next_sequence()
        actor_dict = actor.to_dict() if isinstance(actor, Actor) else dict(actor)
        source_event_ids = [state.last_event_id for state in source_states]
        event_data: dict[str, Any] = {
            "event_id": event_id or str(uuid4()),
            "sequence": sequence,
            "timestamp": self._normalize_timestamp(timestamp, sequence=sequence),
            "actor": actor_dict,
            "tenant_id": source_states[0].tenant_id,
            "memory_id": new_memory_id,
            "event_type": "promoted",
            "memory_class": "semantic",
            "previous_events": list(source_event_ids),
            "promoted_from_memory_ids": [state.memory_id for state in source_states],
            "promoted_from_event_ids": list(source_event_ids),
            "payload": payload,
            "payload_hash": canonical_payload_hash(payload),
        }
        if evidence_refs is not None:
            event_data["evidence_refs"] = evidence_refs
        event = self.ingest_event(
            event_data,
            expected_tenant_id=source_states[0].tenant_id,
            trusted_context=trusted_context,
        )
        record = self._peek_record(
            new_memory_id,
            policy_context=policy_context,
            trusted_context=trusted_context,
        )
        result = {
            "outcome": "appended",
            "record": record,
            "denial_reason": None,
            "event": event.to_dict(),
            "promoted_memory_id": new_memory_id,
            "source_memory_ids": [state.memory_id for state in source_states],
        }
        self._emit_audit(
            {
                "type": "memory.promote",
                "tenant_id": ctx.tenant_id,
                "memory_ids": [state.memory_id for state in source_states],
                "promoted_memory_id": new_memory_id,
                "outcome": "appended",
                "denial_reason": None,
                "event_id": event.event_id,
            }
        )
        return result

    def propose_merge(
        self,
        memory_ids: list[str] | tuple[str, ...],
        *,
        actor: Mapping[str, Any] | Actor,
        payload: Any,
        resolver_kind: str = DEFAULT_RESOLVER_KIND,
        resolution_reason: str | None = None,
        policy_context: Mapping[str, Any] | None = None,
        trusted_context: Mapping[str, Any] | None = None,
        merged_memory_id: str | None = None,
        event_id: str | None = None,
        timestamp: Mapping[str, Any] | None = None,
        evidence_refs: list[Mapping[str, Any]] | None = None,
    ) -> dict[str, Any]:
        if len(memory_ids) < 2:
            raise ValueError("memory_ids must include at least two source memories")
        normalized_memory_ids = [str(memory_id) for memory_id in memory_ids]
        if len(set(normalized_memory_ids)) != len(normalized_memory_ids):
            raise ValueError("memory_ids must not contain duplicates")

        ctx = self._build_policy_context(policy_context, trusted_context=trusted_context)
        state_map = self.state_map()
        source_states: list[MemoryState] = []
        source_denials: dict[str, str] = {}
        for memory_id in normalized_memory_ids:
            state = state_map.get(memory_id)
            if state is None:
                source_denials[memory_id] = "memory_not_found"
                continue
            outcome = get_outcome(memory_id, state_map, ctx)
            if outcome.record is None:
                source_denials[memory_id] = outcome.denial_reason or "merge_denied"
                continue
            if not state.queryable_payload_present:
                source_denials[memory_id] = "queryable_payload_required_for_merge"
                continue
            source_states.append(state)
        if not source_denials:
            for source_memory_id in normalized_memory_ids:
                peers = [memory_id for memory_id in normalized_memory_ids if memory_id != source_memory_id]
                if not any(
                    self._has_conflict_relationship(source_memory_id, peer_memory_id, state_map)
                    for peer_memory_id in peers
                ):
                    source_denials[source_memory_id] = "conflict_edge_required"
        if source_denials:
            denial_reason = next(iter(source_denials.values()))
            result = {
                "outcome": "denied",
                "record": None,
                "denial_reason": denial_reason,
                "source_denials": source_denials,
            }
            self._emit_audit(
                {
                    "type": "memory.merge_propose",
                    "tenant_id": ctx.tenant_id,
                    "memory_ids": list(normalized_memory_ids),
                    "outcome": "denied",
                    "denial_reason": denial_reason,
                    "source_denials": dict(source_denials),
                }
            )
            return result

        tenant_ids = {state.tenant_id for state in source_states}
        if len(tenant_ids) != 1:
            raise ValueError("merge proposal sources must belong to a single tenant")
        new_memory_id = merged_memory_id or str(uuid4())
        if new_memory_id in state_map:
            raise ValueError("merged_memory_id already exists")
        source_event_ids = [state.last_event_id for state in source_states]
        sequence = self._next_sequence()
        actor_dict = actor.to_dict() if isinstance(actor, Actor) else dict(actor)
        event_data: dict[str, Any] = {
            "event_id": event_id or str(uuid4()),
            "sequence": sequence,
            "timestamp": self._normalize_timestamp(timestamp, sequence=sequence),
            "actor": actor_dict,
            "tenant_id": source_states[0].tenant_id,
            "memory_id": new_memory_id,
            "event_type": "merge_proposed",
            "memory_class": "semantic",
            "previous_events": list(source_event_ids),
            "resolved_from_memory_ids": [state.memory_id for state in source_states],
            "resolved_from_event_ids": list(source_event_ids),
            "resolver_kind": str(resolver_kind),
            "payload": payload,
            "payload_hash": canonical_payload_hash(payload),
        }
        if resolution_reason is not None:
            event_data["resolution_reason"] = resolution_reason
        if evidence_refs is not None:
            event_data["evidence_refs"] = evidence_refs
        event = self.ingest_event(
            event_data,
            expected_tenant_id=source_states[0].tenant_id,
            trusted_context=trusted_context,
        )
        record = self._peek_record(
            new_memory_id,
            policy_context=policy_context,
            trusted_context=trusted_context,
        )
        result = {
            "outcome": "appended",
            "record": record,
            "denial_reason": None,
            "event": event.to_dict(),
            "merged_memory_id": new_memory_id,
            "source_memory_ids": [state.memory_id for state in source_states],
        }
        self._emit_audit(
            {
                "type": "memory.merge_propose",
                "tenant_id": ctx.tenant_id,
                "memory_ids": [state.memory_id for state in source_states],
                "merged_memory_id": new_memory_id,
                "outcome": "appended",
                "denial_reason": None,
                "event_id": event.event_id,
            }
        )
        return result

    def approve_merge(
        self,
        memory_id: str,
        *,
        actor: Mapping[str, Any] | Actor,
        policy_context: Mapping[str, Any] | None = None,
        trusted_context: Mapping[str, Any] | None = None,
        event_id: str | None = None,
        timestamp: Mapping[str, Any] | None = None,
        evidence_refs: list[Mapping[str, Any]] | None = None,
        resolution_reason: str | None = None,
    ) -> dict[str, Any]:
        ctx = self._build_policy_context(policy_context, trusted_context=trusted_context)
        state = self.state_map().get(memory_id)
        if state is None:
            result = self._mutation_result(outcome="not_found", denial_reason="memory_not_found")
            self._emit_audit(
                {
                    "type": "memory.merge_approve",
                    "tenant_id": ctx.tenant_id,
                    "memory_id": memory_id,
                    "outcome": "not_found",
                    "denial_reason": "memory_not_found",
                }
            )
            return result
        if ctx.tenant_id is None:
            denial_reason = "tenant_scope_required_default_deny"
            result = self._mutation_result(outcome="denied", denial_reason=denial_reason)
            self._emit_audit(
                {
                    "type": "memory.merge_approve",
                    "tenant_id": ctx.tenant_id,
                    "memory_id": memory_id,
                    "outcome": "denied",
                    "denial_reason": denial_reason,
                }
            )
            return result
        if state.tenant_id != ctx.tenant_id:
            denial_reason = "tenant_scope_mismatch_default_deny"
            result = self._mutation_result(outcome="denied", denial_reason=denial_reason)
            self._emit_audit(
                {
                    "type": "memory.merge_approve",
                    "tenant_id": ctx.tenant_id,
                    "memory_id": memory_id,
                    "outcome": "denied",
                    "denial_reason": denial_reason,
                }
            )
            return result
        if state.last_event_type != "merge_proposed" or not state.conflict_open:
            denial_reason = "merge_proposal_not_open"
            result = self._mutation_result(outcome="denied", denial_reason=denial_reason)
            self._emit_audit(
                {
                    "type": "memory.merge_approve",
                    "tenant_id": ctx.tenant_id,
                    "memory_id": memory_id,
                    "outcome": "denied",
                    "denial_reason": denial_reason,
                }
            )
            return result
        event = self._append_dynamic_event(
            memory_id=memory_id,
            event_type="merge_approved",
            actor=actor,
            payload_hash=state.payload_hash,
            trusted_context=trusted_context,
            event_id=event_id,
            timestamp=timestamp,
            evidence_refs=evidence_refs,
            resolution_reason=resolution_reason,
        )
        record = self._peek_record(
            memory_id,
            policy_context=policy_context,
            trusted_context=trusted_context,
        )
        result = self._mutation_result(outcome="appended", record=record, event=event)
        self._emit_audit(
            {
                "type": "memory.merge_approve",
                "tenant_id": ctx.tenant_id,
                "memory_id": memory_id,
                "outcome": "appended",
                "denial_reason": None,
                "event_id": event.event_id,
            }
        )
        return result

    def reject_merge(
        self,
        memory_id: str,
        *,
        actor: Mapping[str, Any] | Actor,
        policy_context: Mapping[str, Any] | None = None,
        trusted_context: Mapping[str, Any] | None = None,
        event_id: str | None = None,
        timestamp: Mapping[str, Any] | None = None,
        evidence_refs: list[Mapping[str, Any]] | None = None,
        resolution_reason: str | None = None,
    ) -> dict[str, Any]:
        ctx = self._build_policy_context(policy_context, trusted_context=trusted_context)
        state = self.state_map().get(memory_id)
        if state is None:
            result = self._mutation_result(outcome="not_found", denial_reason="memory_not_found")
            self._emit_audit(
                {
                    "type": "memory.merge_reject",
                    "tenant_id": ctx.tenant_id,
                    "memory_id": memory_id,
                    "outcome": "not_found",
                    "denial_reason": "memory_not_found",
                }
            )
            return result
        if ctx.tenant_id is None:
            denial_reason = "tenant_scope_required_default_deny"
            result = self._mutation_result(outcome="denied", denial_reason=denial_reason)
            self._emit_audit(
                {
                    "type": "memory.merge_reject",
                    "tenant_id": ctx.tenant_id,
                    "memory_id": memory_id,
                    "outcome": "denied",
                    "denial_reason": denial_reason,
                }
            )
            return result
        if state.tenant_id != ctx.tenant_id:
            denial_reason = "tenant_scope_mismatch_default_deny"
            result = self._mutation_result(outcome="denied", denial_reason=denial_reason)
            self._emit_audit(
                {
                    "type": "memory.merge_reject",
                    "tenant_id": ctx.tenant_id,
                    "memory_id": memory_id,
                    "outcome": "denied",
                    "denial_reason": denial_reason,
                }
            )
            return result
        if state.last_event_type != "merge_proposed" or not state.conflict_open:
            denial_reason = "merge_proposal_not_open"
            result = self._mutation_result(outcome="denied", denial_reason=denial_reason)
            self._emit_audit(
                {
                    "type": "memory.merge_reject",
                    "tenant_id": ctx.tenant_id,
                    "memory_id": memory_id,
                    "outcome": "denied",
                    "denial_reason": denial_reason,
                }
            )
            return result
        event = self._append_dynamic_event(
            memory_id=memory_id,
            event_type="merge_rejected",
            actor=actor,
            payload_hash=state.payload_hash,
            trusted_context=trusted_context,
            event_id=event_id,
            timestamp=timestamp,
            evidence_refs=evidence_refs,
            resolution_reason=resolution_reason,
        )
        record = self._peek_record(
            memory_id,
            policy_context=policy_context,
            trusted_context=trusted_context,
        )
        result = self._mutation_result(outcome="appended", record=record, event=event)
        self._emit_audit(
            {
                "type": "memory.merge_reject",
                "tenant_id": ctx.tenant_id,
                "memory_id": memory_id,
                "outcome": "appended",
                "denial_reason": None,
                "event_id": event.event_id,
            }
        )
        return result

    def link(
        self,
        memory_id: str,
        related_memory_id: str,
        *,
        actor: Mapping[str, Any] | Actor,
        policy_context: Mapping[str, Any] | None = None,
        trusted_context: Mapping[str, Any] | None = None,
        event_id: str | None = None,
        timestamp: Mapping[str, Any] | None = None,
        evidence_refs: list[Mapping[str, Any]] | None = None,
        edge_weight: float | None = None,
        edge_reason: str | None = None,
    ) -> dict[str, Any]:
        ctx, outcome = self._policy_outcome(
            memory_id,
            policy_context=policy_context,
            trusted_context=trusted_context,
        )
        if outcome.outcome != "allowed" or outcome.record is None:
            result = self._mutation_result(
                outcome=outcome.outcome,
                denial_reason=outcome.denial_reason,
            )
            self._emit_audit(
                {
                    "type": "memory.link",
                    "tenant_id": ctx.tenant_id,
                    "memory_id": memory_id,
                    "target_memory_id": related_memory_id,
                    "outcome": outcome.outcome,
                    "denial_reason": outcome.denial_reason,
                }
            )
            return result
        event = self._append_dynamic_event(
            memory_id=memory_id,
            event_type="linked",
            actor=actor,
            payload_hash=self.state_map()[memory_id].payload_hash,
            trusted_context=trusted_context,
            event_id=event_id,
            timestamp=timestamp,
            evidence_refs=evidence_refs,
            target_memory_id=related_memory_id,
            edge_weight=edge_weight,
            edge_reason=edge_reason,
        )
        record = self._peek_record(
            memory_id,
            policy_context=policy_context,
            trusted_context=trusted_context,
        )
        result = self._mutation_result(outcome="appended", record=record, event=event)
        self._emit_audit(
            {
                "type": "memory.link",
                "tenant_id": ctx.tenant_id,
                "memory_id": memory_id,
                "target_memory_id": related_memory_id,
                "outcome": "appended",
                "denial_reason": None,
                "event_id": event.event_id,
            }
        )
        return result

    def reinforce(
        self,
        memory_id: str,
        *,
        actor: Mapping[str, Any] | Actor,
        related_memory_id: str | None = None,
        policy_context: Mapping[str, Any] | None = None,
        trusted_context: Mapping[str, Any] | None = None,
        event_id: str | None = None,
        timestamp: Mapping[str, Any] | None = None,
        evidence_refs: list[Mapping[str, Any]] | None = None,
        edge_weight: float | None = None,
        edge_reason: str | None = None,
    ) -> dict[str, Any]:
        ctx, outcome = self._policy_outcome(
            memory_id,
            policy_context=policy_context,
            trusted_context=trusted_context,
        )
        if outcome.outcome != "allowed" or outcome.record is None:
            result = self._mutation_result(
                outcome=outcome.outcome,
                denial_reason=outcome.denial_reason,
            )
            self._emit_audit(
                {
                    "type": "memory.reinforce",
                    "tenant_id": ctx.tenant_id,
                    "memory_id": memory_id,
                    "target_memory_id": related_memory_id,
                    "outcome": outcome.outcome,
                    "denial_reason": outcome.denial_reason,
                }
            )
            return result
        event = self._append_dynamic_event(
            memory_id=memory_id,
            event_type="reinforced",
            actor=actor,
            payload_hash=self.state_map()[memory_id].payload_hash,
            trusted_context=trusted_context,
            event_id=event_id,
            timestamp=timestamp,
            evidence_refs=evidence_refs,
            target_memory_id=related_memory_id,
            edge_weight=edge_weight,
            edge_reason=edge_reason,
        )
        record = self._peek_record(
            memory_id,
            policy_context=policy_context,
            trusted_context=trusted_context,
        )
        result = self._mutation_result(outcome="appended", record=record, event=event)
        self._emit_audit(
            {
                "type": "memory.reinforce",
                "tenant_id": ctx.tenant_id,
                "memory_id": memory_id,
                "target_memory_id": related_memory_id,
                "outcome": "appended",
                "denial_reason": None,
                "event_id": event.event_id,
            }
        )
        return result

    def conflict(
        self,
        memory_id: str,
        conflicting_memory_id: str,
        *,
        actor: Mapping[str, Any] | Actor,
        policy_context: Mapping[str, Any] | None = None,
        trusted_context: Mapping[str, Any] | None = None,
        event_id: str | None = None,
        timestamp: Mapping[str, Any] | None = None,
        evidence_refs: list[Mapping[str, Any]] | None = None,
        edge_weight: float | None = None,
        edge_reason: str | None = None,
    ) -> dict[str, Any]:
        ctx, outcome = self._policy_outcome(
            memory_id,
            policy_context=policy_context,
            trusted_context=trusted_context,
        )
        if outcome.outcome != "allowed" or outcome.record is None:
            result = self._mutation_result(
                outcome=outcome.outcome,
                denial_reason=outcome.denial_reason,
            )
            self._emit_audit(
                {
                    "type": "memory.conflict",
                    "tenant_id": ctx.tenant_id,
                    "memory_id": memory_id,
                    "target_memory_id": conflicting_memory_id,
                    "outcome": outcome.outcome,
                    "denial_reason": outcome.denial_reason,
                }
            )
            return result
        event = self._append_dynamic_event(
            memory_id=memory_id,
            event_type="conflicted",
            actor=actor,
            payload_hash=self.state_map()[memory_id].payload_hash,
            trusted_context=trusted_context,
            event_id=event_id,
            timestamp=timestamp,
            evidence_refs=evidence_refs,
            target_memory_id=conflicting_memory_id,
            edge_weight=edge_weight,
            edge_reason=edge_reason,
        )
        record = self._peek_record(
            memory_id,
            policy_context=policy_context,
            trusted_context=trusted_context,
        )
        result = self._mutation_result(outcome="appended", record=record, event=event)
        self._emit_audit(
            {
                "type": "memory.conflict",
                "tenant_id": ctx.tenant_id,
                "memory_id": memory_id,
                "target_memory_id": conflicting_memory_id,
                "outcome": "appended",
                "denial_reason": None,
                "event_id": event.event_id,
            }
        )
        return result

    def recall(
        self,
        memory_id: str,
        *,
        actor: Mapping[str, Any] | Actor,
        policy_context: Mapping[str, Any] | None = None,
        trusted_context: Mapping[str, Any] | None = None,
        event_id: str | None = None,
        timestamp: Mapping[str, Any] | None = None,
        evidence_refs: list[Mapping[str, Any]] | None = None,
    ) -> dict[str, Any]:
        ctx, outcome = self._policy_outcome(
            memory_id,
            policy_context=policy_context,
            trusted_context=trusted_context,
        )
        if outcome.outcome != "allowed" or outcome.record is None:
            result = self._mutation_result(
                outcome=outcome.outcome,
                denial_reason=outcome.denial_reason,
            )
            self._emit_audit(
                {
                    "type": "memory.recall",
                    "tenant_id": ctx.tenant_id,
                    "memory_id": memory_id,
                    "outcome": outcome.outcome,
                    "denial_reason": outcome.denial_reason,
                }
            )
            return result
        event = self._append_dynamic_event(
            memory_id=memory_id,
            event_type="recalled",
            actor=actor,
            payload_hash=self.state_map()[memory_id].payload_hash,
            trusted_context=trusted_context,
            event_id=event_id,
            timestamp=timestamp,
            evidence_refs=evidence_refs,
        )
        record = self._peek_record(
            memory_id,
            policy_context=policy_context,
            trusted_context=trusted_context,
        )
        result = self._mutation_result(
            outcome="appended",
            record=record,
            event=event,
        )
        self._emit_audit(
            {
                "type": "memory.recall",
                "tenant_id": ctx.tenant_id,
                "memory_id": memory_id,
                "outcome": "appended",
                "denial_reason": None,
                "event_id": event.event_id,
            }
        )
        return result

    def reconsolidate(
        self,
        memory_id: str,
        *,
        actor: Mapping[str, Any] | Actor,
        payload_hash: str,
        payload: Any | None = None,
        policy_context: Mapping[str, Any] | None = None,
        trusted_context: Mapping[str, Any] | None = None,
        event_id: str | None = None,
        timestamp: Mapping[str, Any] | None = None,
        evidence_refs: list[Mapping[str, Any]] | None = None,
        signature: Mapping[str, Any] | None = None,
        attestation: Mapping[str, Any] | None = None,
    ) -> dict[str, Any]:
        ctx, outcome = self._policy_outcome(
            memory_id,
            policy_context=policy_context,
            trusted_context=trusted_context,
        )
        if outcome.outcome != "allowed" or outcome.record is None:
            result = self._mutation_result(
                outcome=outcome.outcome,
                denial_reason=outcome.denial_reason,
            )
            self._emit_audit(
                {
                    "type": "memory.reconsolidate",
                    "tenant_id": ctx.tenant_id,
                    "memory_id": memory_id,
                    "outcome": outcome.outcome,
                    "denial_reason": outcome.denial_reason,
                }
            )
            return result
        event = self._append_dynamic_event(
            memory_id=memory_id,
            event_type="reconsolidated",
            actor=actor,
            payload_hash=payload_hash,
            payload=payload,
            trusted_context=trusted_context,
            event_id=event_id,
            timestamp=timestamp,
            evidence_refs=evidence_refs,
            signature=signature,
            attestation=attestation,
        )
        record = self._peek_record(
            memory_id,
            policy_context=policy_context,
            trusted_context=trusted_context,
        )
        result = self._mutation_result(
            outcome="appended",
            record=record,
            event=event,
        )
        self._emit_audit(
            {
                "type": "memory.reconsolidate",
                "tenant_id": ctx.tenant_id,
                "memory_id": memory_id,
                "outcome": "appended",
                "denial_reason": None,
                "event_id": event.event_id,
            }
        )
        return result

    def explain(
        self,
        memory_id: str,
        *,
        policy_context: Mapping[str, Any] | None = None,
        trusted_context: Mapping[str, Any] | None = None,
    ) -> list[dict[str, Any]]:
        ctx = self._build_policy_context(policy_context, trusted_context=trusted_context)
        state_map = self.state_map()
        outcome = get_outcome(memory_id, state_map, ctx)
        if outcome.record is None:
            self._emit_audit(
                {
                    "type": "memory.explain",
                    "tenant_id": ctx.tenant_id,
                    "memory_id": memory_id,
                    "outcome": outcome.outcome,
                    "denial_reason": outcome.denial_reason,
                    "trace_count": 0,
                }
            )
            return []
        if hasattr(self.log, "events_for_memory"):
            explain_events = self.log.events_for_memory(memory_id, ctx.tenant_id)
        else:
            explain_events = self._load_all_events_cached()
        trace = explain(memory_id, explain_events, tenant_id=ctx.tenant_id)
        self._emit_audit(
            {
                "type": "memory.explain",
                "tenant_id": ctx.tenant_id,
                "memory_id": memory_id,
                "outcome": "allowed",
                "denial_reason": outcome.denial_reason,
                "trace_count": len(trace),
            }
        )
        return trace

    def export_snapshot(
        self,
        *,
        policy_context: Mapping[str, Any] | None = None,
        trusted_context: Mapping[str, Any] | None = None,
    ) -> dict[str, Any]:
        ctx = self._build_policy_context(policy_context, trusted_context=trusted_context)
        snapshot = export_sbom_snapshot(self.state_map(), ctx)
        self._emit_audit(
            {
                "type": "memory.export.snapshot",
                "tenant_id": ctx.tenant_id,
                "record_count": int(snapshot.get("count", 0)),
            }
        )
        return snapshot

    def export_provenance(
        self,
        *,
        policy_context: Mapping[str, Any] | None = None,
        trusted_context: Mapping[str, Any] | None = None,
        sequence_range: tuple[int, int] | None = None,
        memory_id: str | None = None,
    ) -> dict[str, Any]:
        ctx = self._build_policy_context(policy_context, trusted_context=trusted_context)
        if ctx.tenant_id is None and not ctx.can_override():
            denied = {
                "artifact_type": "provenance_log_slice",
                "count": 0,
                "events": [],
                "denial_reason": "tenant_scope_required_default_deny",
            }
            self._emit_audit(
                {
                    "type": "memory.export.provenance",
                    "tenant_id": ctx.tenant_id,
                    "memory_id": memory_id,
                    "sequence_range": sequence_range,
                    "event_count": 0,
                    "denial_reason": denied["denial_reason"],
                    "load_strategy": "denied",
                }
            )
            return denied
        events: tuple[EventEnvelope, ...]
        load_strategy = "full"
        if memory_id is not None and hasattr(self.log, "events_for_memory"):
            if sequence_range is not None:
                start, end = sequence_range
                events = self.log.events_for_memory_in_sequence_range(
                    memory_id,
                    ctx.tenant_id,
                    start=start,
                    end=end,
                )
                load_strategy = "memory_scoped"
            else:
                events = self.log.events_for_memory(memory_id, ctx.tenant_id)
                load_strategy = "memory_scoped"
        elif sequence_range is not None and hasattr(self.log, "events_in_sequence_range"):
            start, end = sequence_range
            events = self.log.events_in_sequence_range(start=start, end=end)
            load_strategy = "sequence_range"
        else:
            events = self._load_all_events_cached()
            load_strategy = "full"
        provenance = export_provenance_log(
            events,
            sequence_range=sequence_range,
            memory_id=memory_id,
            tenant_id=ctx.tenant_id,
        )
        self._emit_audit(
            {
                "type": "memory.export.provenance",
                "tenant_id": ctx.tenant_id,
                "memory_id": memory_id,
                "sequence_range": sequence_range,
                "event_count": int(provenance.get("count", 0)),
                "denial_reason": provenance.get("denial_reason"),
                "load_strategy": load_strategy,
            }
        )
        return provenance

    def close(self) -> None:
        if self._query_index_cache is not None:
            close_backend = getattr(self._query_index_cache, "close", None)
            if callable(close_backend):
                close_backend()
        close_fn = getattr(self.log, "close", None)
        if callable(close_fn):
            close_fn()


def open_runtime(
    *,
    db_path: str | Path | None = None,
    event_backend: str | None = None,
    event_backend_dsn: str | None = None,
    event_backend_schema: str = "amf_core",
    bootstrap_event_backend: bool = False,
    keyring: Mapping[str, bytes | str | Mapping[str, Any] | KeyMaterial] | None = None,
    audit_sink: AuditSink | None = None,
    query_backend: str = "inmemory",
    query_backend_dsn: str | None = None,
    query_backend_schema: str = "amf_query",
    bootstrap_query_backend: bool = False,
    embedder: TextEmbedder | None = None,
) -> MemoryRuntime:
    log: EventLog
    if event_backend is None:
        if db_path is None:
            log = AppendOnlyEventLog()
        else:
            log = SQLiteEventLog(db_path=db_path)
    elif event_backend == "memory":
        if db_path is not None:
            raise ValueError("db_path cannot be combined with event_backend='memory'")
        log = AppendOnlyEventLog()
    elif event_backend == "sqlite":
        if db_path is None:
            raise ValueError("db_path is required when event_backend='sqlite'")
        log = SQLiteEventLog(db_path=db_path)
    elif event_backend == "postgres":
        if db_path is not None:
            raise ValueError("db_path cannot be combined with event_backend='postgres'")
        if event_backend_dsn is None:
            raise ValueError("event_backend_dsn is required when event_backend='postgres'")
        log = PostgresEventLog(
            event_backend_dsn,
            schema=event_backend_schema,
            bootstrap=bootstrap_event_backend,
        )
    else:
        raise ValueError("event_backend must be one of memory, sqlite, or postgres")
    runtime = MemoryRuntime(
        log=log,
        keyring=dict(keyring or {}),
        audit_sink=audit_sink,
        query_backend_name=query_backend,
        query_backend_dsn=query_backend_dsn,
        query_backend_schema=query_backend_schema,
        bootstrap_query_backend=bootstrap_query_backend,
        embedder=embedder,
    )
    return runtime
