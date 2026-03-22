"""In-memory runtime state container for service and CLI surfaces."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Mapping

from .crypto import KeyMaterial, verify_event_signature
from .decay import DecayPolicy
from .events import EventEnvelope
from .explain import explain
from .export import export_provenance_log, export_sbom_snapshot
from .importer import append_imported_records
from .log import AppendOnlyEventLog, EventLog
from .policy import PolicyContext
from .replay import MemoryState, replay_events
from .retrieval import get as retrieval_get
from .retrieval import query as retrieval_query
from .sqlite_store import SQLiteEventLog


@dataclass
class MemoryRuntime:
    log: EventLog = field(default_factory=AppendOnlyEventLog)
    keyring: dict[str, bytes | str | KeyMaterial] = field(default_factory=dict)

    def _key_resolver(self, key_id: str) -> bytes | str | KeyMaterial | None:
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

    def state_map(self) -> dict[str, MemoryState]:
        return replay_events(
            self.log.all_events(),
            signature_states=self.log.signature_states(),
        )

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
        records = retrieval_query(
            self.state_map(),
            ctx,
            trust_states=trust_states,
            limit=limit,
        )
        return [record.__dict__ for record in records]

    def get(
        self,
        memory_id: str,
        *,
        policy_context: Mapping[str, Any] | None = None,
        trusted_context: Mapping[str, Any] | None = None,
    ) -> dict[str, Any] | None:
        ctx = self._build_policy_context(policy_context, trusted_context=trusted_context)
        record = retrieval_get(memory_id, self.state_map(), ctx)
        return None if record is None else record.__dict__

    def explain(
        self,
        memory_id: str,
        *,
        policy_context: Mapping[str, Any] | None = None,
        trusted_context: Mapping[str, Any] | None = None,
    ) -> list[dict[str, Any]]:
        ctx = self._build_policy_context(policy_context, trusted_context=trusted_context)
        state_map = self.state_map()
        record = retrieval_get(memory_id, state_map, ctx)
        if record is None:
            return []
        return explain(memory_id, self.log.all_events(), tenant_id=ctx.tenant_id)

    def export_snapshot(
        self,
        *,
        policy_context: Mapping[str, Any] | None = None,
        trusted_context: Mapping[str, Any] | None = None,
    ) -> dict[str, Any]:
        ctx = self._build_policy_context(policy_context, trusted_context=trusted_context)
        return export_sbom_snapshot(self.state_map(), ctx)

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
            return {
                "artifact_type": "provenance_log_slice",
                "count": 0,
                "events": [],
                "denial_reason": "tenant_scope_required_default_deny",
            }
        return export_provenance_log(
            self.log.all_events(),
            sequence_range=sequence_range,
            memory_id=memory_id,
            tenant_id=ctx.tenant_id,
        )


def open_runtime(
    *,
    db_path: str | Path | None = None,
    keyring: Mapping[str, bytes | str | KeyMaterial] | None = None,
) -> MemoryRuntime:
    log: EventLog
    if db_path is None:
        log = AppendOnlyEventLog()
    else:
        log = SQLiteEventLog(db_path=db_path)
    return MemoryRuntime(log=log, keyring=dict(keyring or {}))
