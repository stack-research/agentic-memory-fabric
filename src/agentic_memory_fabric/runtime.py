"""In-memory runtime state container for service and CLI surfaces."""

from __future__ import annotations

from datetime import datetime, timezone
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Mapping
from uuid import uuid4

from .crypto import KeyMaterial, verify_event_signature
from .decay import DecayPolicy
from .events import Actor, EventEnvelope
from .explain import explain
from .export import export_provenance_log, export_sbom_snapshot
from .importer import append_imported_records
from .log import AppendOnlyEventLog, EventLog
from .policy import (
    ATTESTATION_TRUST_LEVELS,
    PolicyContext,
    evaluate_query_gate,
)
from .query_index import InMemoryQueryIndex, QueryIndex
from .replay import MemoryState, replay_events
from .retrieval import get_outcome, query_with_summary, to_retrieval_record
from .sqlite_store import SQLiteEventLog

AuditSink = Callable[[Mapping[str, Any]], None]


@dataclass
class MemoryRuntime:
    log: EventLog = field(default_factory=AppendOnlyEventLog)
    keyring: dict[str, bytes | str | Mapping[str, Any] | KeyMaterial] = field(default_factory=dict)
    audit_sink: AuditSink | None = None
    _state_cache: dict[str, MemoryState] | None = field(default=None, init=False, repr=False)
    _events_cache: tuple[EventEnvelope, ...] | None = field(default=None, init=False, repr=False)
    _query_index_cache: QueryIndex | None = field(default=None, init=False, repr=False)

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
        if event.event_type not in {"recalled", "reconsolidated"}:
            return
        state = self.state_map().get(event.memory_id)
        if state is None:
            raise ValueError(f"{event.event_type} events require an existing memory head")
        if tuple(event.previous_events) != (state.last_event_id,):
            raise ValueError(
                f"{event.event_type} events must point to the current memory head"
            )
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

    def _query_index(self) -> QueryIndex:
        if self._query_index_cache is None:
            self._query_index_cache = InMemoryQueryIndex.build(self.state_map())
        return self._query_index_cache

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
            "trust_state",
            "lifecycle_state",
            "signature_state",
            "version",
            "queryable_payload_present",
        }
        for key, expected in structured_filter.items():
            if key not in allowed_fields:
                raise ValueError(f"unsupported structured_filter field: {key}")
            if getattr(state, key) != expected:
                return False
        return True

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
        self._validate_dynamic_event(event)
        self.log.append(event, signature_verifier=self._signature_verifier)
        self._invalidate_read_model_cache()
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
        )
        self._invalidate_read_model_cache()
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
    ) -> dict[str, Any]:
        ctx = self._build_policy_context(policy_context, trusted_context=trusted_context)
        gate = evaluate_query_gate(ctx)
        if not gate.allowed:
            denied = {
                "count": 0,
                "records": [],
                "query_allowed": False,
                "query_denial_reason": gate.denial_reason,
                "query_override_used": gate.override_used,
            }
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
                }
            )
            return denied
        state_map = self.state_map()
        if structured_filter is not None and not isinstance(structured_filter, Mapping):
            raise ValueError("structured_filter must be an object when provided")
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
            considered = 0
            trust_state_filtered = 0
            override_used_count = 0
            denied_by_reason: dict[str, int] = {}
            records_out: list[dict[str, Any]] = []
            hits = self._query_index().search(
                query_text=str(query_text),
                tenant_id=ctx.tenant_id,
                limit=None,
            )
            for hit in hits:
                state = state_map.get(hit.memory_id)
                if state is None:
                    continue
                considered += 1
                if state.last_event_id != hit.indexed_event_id:
                    continue
                if trust_states is not None and state.trust_state not in trust_states:
                    trust_state_filtered += 1
                    continue
                if not self._matches_structured_filter(state, structured_filter):
                    continue
                outcome = get_outcome(hit.memory_id, state_map, ctx)
                if outcome.record is None:
                    reason = outcome.denial_reason or "policy_denied"
                    denied_by_reason[reason] = denied_by_reason.get(reason, 0) + 1
                    continue
                decision_record = to_retrieval_record(
                    state,
                    why_sound=outcome.record.why_sound,
                    denial_reason=outcome.record.denial_reason,
                    override_used=outcome.record.override_used,
                    retrieval_score=hit.retrieval_score,
                    retrieval_mode=hit.retrieval_mode,
                    indexed_event_id=hit.indexed_event_id,
                )
                if decision_record.override_used:
                    override_used_count += 1
                records_out.append(decision_record.__dict__)
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
                "query_text_present": bool(query_text and str(query_text).strip()),
                "query_allowed": True,
                "query_denial_reason": gate.denial_reason,
                "query_override_used": gate.override_used,
                "uncertainty_score": ctx.uncertainty_score,
                "uncertainty_threshold": ctx.uncertainty_threshold,
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
        close_fn = getattr(self.log, "close", None)
        if callable(close_fn):
            close_fn()


def open_runtime(
    *,
    db_path: str | Path | None = None,
    keyring: Mapping[str, bytes | str | Mapping[str, Any] | KeyMaterial] | None = None,
    audit_sink: AuditSink | None = None,
) -> MemoryRuntime:
    log: EventLog
    if db_path is None:
        log = AppendOnlyEventLog()
    else:
        log = SQLiteEventLog(db_path=db_path)
    return MemoryRuntime(log=log, keyring=dict(keyring or {}), audit_sink=audit_sink)
