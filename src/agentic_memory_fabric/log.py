"""Append-only event log primitives."""

from __future__ import annotations

from dataclasses import dataclass, field

from .events import EventEnvelope


@dataclass
class AppendOnlyEventLog:
    _events: list[EventEnvelope] = field(default_factory=list)
    _event_ids: set[str] = field(default_factory=set)

    def append(self, event: EventEnvelope) -> None:
        expected_sequence = len(self._events) + 1
        if event.sequence != expected_sequence:
            raise ValueError(
                f"event sequence must be contiguous; expected {expected_sequence}, got {event.sequence}"
            )
        if event.event_id in self._event_ids:
            raise ValueError(f"duplicate event_id: {event.event_id}")
        self._events.append(event)
        self._event_ids.add(event.event_id)

    def all_events(self) -> tuple[EventEnvelope, ...]:
        return tuple(self._events)

    def __len__(self) -> int:
        return len(self._events)
