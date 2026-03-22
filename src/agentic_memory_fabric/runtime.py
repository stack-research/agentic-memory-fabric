"""In-memory runtime state container for service and CLI surfaces."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Mapping

from .crypto import verify_event_signature
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
    keyring: dict[str, bytes | str] = field(default_factory=dict)

    def _key_resolver(self, key_id: str) -> bytes | str | None:
        return self.keyring.get(key_id)

    def _signature_verifier(self, event: EventEnvelope) -> str:
        return verify_event_signature(event, key_resolver=self._key_resolver)

    def _build_policy_context(self, raw: Mapping[str, Any] | None = None) -> PolicyContext:
        if raw is None:
            return PolicyContext()
        decay_policy_raw = raw.get("decay_policy")
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
        return PolicyContext(
            role=str(raw.get("role", "runtime")),
            capabilities=frozenset(raw.get("capabilities", [])),
            allow_overrides=bool(raw.get("allow_overrides", False)),
            current_tick=(
                int(raw["current_tick"]) if raw.get("current_tick") is not None else None
            ),
            decay_policy=decay_policy,
        )

    def state_map(self) -> dict[str, MemoryState]:
        return replay_events(
            self.log.all_events(),
            signature_states=self.log.signature_states(),
        )

    def ingest_event(self, event_data: Mapping[str, Any]) -> EventEnvelope:
        event = EventEnvelope.from_dict(event_data)
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
    ) -> tuple[EventEnvelope, ...]:
        if start_sequence is None:
            start_sequence = len(self.log) + 1
        events = append_imported_records(
            self.log,
            records,
            actor=actor,
            start_sequence=start_sequence,
            default_timestamp=default_timestamp,
            default_tick=default_tick,
        )
        return events

    def query(
        self,
        *,
        policy_context: Mapping[str, Any] | None = None,
        trust_states: set[str] | None = None,
        limit: int | None = None,
    ) -> list[dict[str, Any]]:
        ctx = self._build_policy_context(policy_context)
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
    ) -> dict[str, Any] | None:
        ctx = self._build_policy_context(policy_context)
        record = retrieval_get(memory_id, self.state_map(), ctx)
        return None if record is None else record.__dict__

    def explain(self, memory_id: str) -> list[dict[str, Any]]:
        return explain(memory_id, self.log.all_events())

    def export_snapshot(self, *, policy_context: Mapping[str, Any] | None = None) -> dict[str, Any]:
        ctx = self._build_policy_context(policy_context)
        return export_sbom_snapshot(self.state_map(), ctx)

    def export_provenance(
        self,
        *,
        sequence_range: tuple[int, int] | None = None,
        memory_id: str | None = None,
    ) -> dict[str, Any]:
        return export_provenance_log(
            self.log.all_events(),
            sequence_range=sequence_range,
            memory_id=memory_id,
        )


def open_runtime(
    *,
    db_path: str | Path | None = None,
    keyring: Mapping[str, bytes | str] | None = None,
) -> MemoryRuntime:
    log: EventLog
    if db_path is None:
        log = AppendOnlyEventLog()
    else:
        log = SQLiteEventLog(db_path=db_path)
    return MemoryRuntime(log=log, keyring=dict(keyring or {}))
