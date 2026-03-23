"""In-memory runtime state container for service and CLI surfaces."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Mapping

from .crypto import KeyMaterial, verify_event_signature
from .decay import DecayPolicy
from .events import EventEnvelope
from .explain import explain
from .export import export_provenance_log, export_sbom_snapshot
from .importer import append_imported_records
from .log import AppendOnlyEventLog, EventLog
from .policy import ATTESTATION_TRUST_LEVELS, PolicyContext
from .replay import MemoryState, replay_events
from .retrieval import get_outcome, query_with_summary
from .sqlite_store import SQLiteEventLog

AuditSink = Callable[[Mapping[str, Any]], None]


@dataclass
class MemoryRuntime:
    log: EventLog = field(default_factory=AppendOnlyEventLog)
    keyring: dict[str, bytes | str | Mapping[str, Any] | KeyMaterial] = field(default_factory=dict)
    audit_sink: AuditSink | None = None
    _state_cache: dict[str, MemoryState] | None = field(default=None, init=False, repr=False)
    _events_cache: tuple[EventEnvelope, ...] | None = field(default=None, init=False, repr=False)

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
        trust_states: set[str] | None = None,
        limit: int | None = None,
    ) -> list[dict[str, Any]]:
        ctx = self._build_policy_context(policy_context, trusted_context=trusted_context)
        records, summary = query_with_summary(
            self.state_map(),
            ctx,
            trust_states=trust_states,
            limit=limit,
        )
        records_out = [record.__dict__ for record in records]
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
            }
        )
        return records_out

    def get(
        self,
        memory_id: str,
        *,
        policy_context: Mapping[str, Any] | None = None,
        trusted_context: Mapping[str, Any] | None = None,
    ) -> dict[str, Any] | None:
        ctx = self._build_policy_context(policy_context, trusted_context=trusted_context)
        outcome = get_outcome(memory_id, self.state_map(), ctx)
        self._emit_audit(
            {
                "type": "memory.get",
                "tenant_id": ctx.tenant_id,
                "memory_id": memory_id,
                "outcome": outcome.outcome,
                "denial_reason": outcome.denial_reason,
            }
        )
        return None if outcome.record is None else outcome.record.__dict__

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
