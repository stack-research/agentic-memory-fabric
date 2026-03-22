"""Append-only event log primitives."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable, Protocol

from .events import EventEnvelope

SignatureVerifier = Callable[[EventEnvelope], str]


class EventLog(Protocol):
    def append(
        self,
        event: EventEnvelope,
        *,
        signature_verifier: SignatureVerifier | None = None,
    ) -> None: ...

    def all_events(self) -> tuple[EventEnvelope, ...]: ...

    def __len__(self) -> int: ...

    def signature_states(self) -> dict[str, str]: ...

    def signature_state_for_event(self, event_id: str) -> str | None: ...


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
    ) -> None:
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

    def __len__(self) -> int:
        return len(self._events)

    def signature_states(self) -> dict[str, str]:
        return dict(self._signature_states)

    def signature_state_for_event(self, event_id: str) -> str | None:
        return self._signature_states.get(event_id)
