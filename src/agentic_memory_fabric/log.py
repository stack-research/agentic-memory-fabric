"""Append-only event log primitives."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable, Protocol

from .events import EventEnvelope

SignatureVerifier = Callable[[EventEnvelope], str]


@dataclass(frozen=True)
class QuerySyncTask:
    tenant_id: str
    memory_id: str
    indexed_event_id: str
    reason: str


@dataclass(frozen=True)
class PendingQuerySync:
    id: int
    tenant_id: str
    memory_id: str
    indexed_event_id: str
    reason: str


class EventLog(Protocol):
    def append(
        self,
        event: EventEnvelope,
        *,
        signature_verifier: SignatureVerifier | None = None,
        query_sync_tasks: tuple[QuerySyncTask, ...] | None = None,
    ) -> None: ...

    def all_events(self) -> tuple[EventEnvelope, ...]: ...

    def all_events_with_signature_states(self) -> tuple[tuple[EventEnvelope, ...], dict[str, str]]: ...

    def events_in_sequence_range(self, *, start: int, end: int) -> tuple[EventEnvelope, ...]: ...

    def events_for_memory(self, memory_id: str, tenant_id: str | None) -> tuple[EventEnvelope, ...]: ...

    def events_for_memory_in_sequence_range(
        self,
        memory_id: str,
        tenant_id: str | None,
        *,
        start: int,
        end: int,
    ) -> tuple[EventEnvelope, ...]: ...

    def __len__(self) -> int: ...

    def signature_states(self) -> dict[str, str]: ...

    def signature_state_for_event(self, event_id: str) -> str | None: ...

    def pending_query_sync(self, *, limit: int | None = None) -> tuple[PendingQuerySync, ...]: ...

    def mark_query_sync_processed(self, row_ids: tuple[int, ...]) -> None: ...

    def query_sync_lag_count(self) -> int: ...


@dataclass
class AppendOnlyEventLog:
    _events: list[EventEnvelope] = field(default_factory=list)
    _event_ids: set[str] = field(default_factory=set)
    _signature_states: dict[str, str] = field(default_factory=dict)

    def append(
        self,
        event: EventEnvelope,
        *,
        signature_verifier: SignatureVerifier | None = None,
        query_sync_tasks: tuple[QuerySyncTask, ...] | None = None,
    ) -> None:
        del query_sync_tasks
        expected_sequence = len(self._events) + 1
        if event.sequence != expected_sequence:
            raise ValueError(
                f"event sequence must be contiguous; expected {expected_sequence}, got {event.sequence}"
            )
        if event.event_id in self._event_ids:
            raise ValueError(f"duplicate event_id: {event.event_id}")
        self._events.append(event)
        self._event_ids.add(event.event_id)
        if signature_verifier is not None:
            self._signature_states[event.event_id] = signature_verifier(event)
        else:
            self._signature_states[event.event_id] = "unsigned" if event.signature is None else "invalid"

    def all_events(self) -> tuple[EventEnvelope, ...]:
        return tuple(self._events)

    def all_events_with_signature_states(self) -> tuple[tuple[EventEnvelope, ...], dict[str, str]]:
        return self.all_events(), self.signature_states()

    def events_in_sequence_range(self, *, start: int, end: int) -> tuple[EventEnvelope, ...]:
        if start < 1 or end < start:
            raise ValueError("sequence range must be (start>=1, end>=start)")
        return tuple(event for event in self._events if start <= event.sequence <= end)

    def __len__(self) -> int:
        return len(self._events)

    def signature_states(self) -> dict[str, str]:
        return dict(self._signature_states)

    def signature_state_for_event(self, event_id: str) -> str | None:
        return self._signature_states.get(event_id)

    def events_for_memory(
        self,
        memory_id: str,
        tenant_id: str | None,
    ) -> tuple[EventEnvelope, ...]:
        out: list[EventEnvelope] = []
        for event in self._events:
            if event.memory_id != memory_id:
                continue
            if tenant_id is not None and event.tenant_id != tenant_id:
                continue
            out.append(event)
        return tuple(out)

    def pending_query_sync(self, *, limit: int | None = None) -> tuple[PendingQuerySync, ...]:
        del limit
        return ()

    def mark_query_sync_processed(self, row_ids: tuple[int, ...]) -> None:
        del row_ids
        return

    def query_sync_lag_count(self) -> int:
        return 0

    def events_for_memory_in_sequence_range(
        self,
        memory_id: str,
        tenant_id: str | None,
        *,
        start: int,
        end: int,
    ) -> tuple[EventEnvelope, ...]:
        if start < 1 or end < start:
            raise ValueError("sequence range must be (start>=1, end>=start)")
        out: list[EventEnvelope] = []
        for event in self._events:
            if event.memory_id != memory_id:
                continue
            if tenant_id is not None and event.tenant_id != tenant_id:
                continue
            if event.sequence < start or event.sequence > end:
                continue
            out.append(event)
        return tuple(out)
