"""SQLite-backed append-only event log."""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path

from .events import EventEnvelope
from .log import SignatureVerifier


class SQLiteEventLog:
    def __init__(self, db_path: str | Path) -> None:
        self._db_path = str(db_path)
        self._conn = sqlite3.connect(self._db_path)
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA busy_timeout=5000")
        self._init_schema()

    def _init_schema(self) -> None:
        self._conn.execute(
            """
            CREATE TABLE IF NOT EXISTS events (
                sequence INTEGER PRIMARY KEY,
                event_id TEXT NOT NULL UNIQUE,
                event_json TEXT NOT NULL,
                signature_state TEXT NOT NULL
            )
            """
        )
        self._conn.commit()

    def append(
        self,
        event: EventEnvelope,
        *,
        signature_verifier: SignatureVerifier | None = None,
    ) -> None:
        expected_sequence = len(self) + 1
        if event.sequence != expected_sequence:
            raise ValueError(
                f"event sequence must be contiguous; expected {expected_sequence}, got {event.sequence}"
            )
        existing = self._conn.execute(
            "SELECT 1 FROM events WHERE event_id = ?",
            (event.event_id,),
        ).fetchone()
        if existing is not None:
            raise ValueError(f"duplicate event_id: {event.event_id}")

        if signature_verifier is not None:
            signature_state = signature_verifier(event)
        else:
            signature_state = "unsigned" if event.signature is None else "invalid"

        self._conn.execute(
            "INSERT INTO events (sequence, event_id, event_json, signature_state) VALUES (?, ?, ?, ?)",
            (
                event.sequence,
                event.event_id,
                json.dumps(event.to_dict(), sort_keys=True),
                signature_state,
            ),
        )
        self._conn.commit()

    def all_events(self) -> tuple[EventEnvelope, ...]:
        rows = self._conn.execute(
            "SELECT event_json FROM events ORDER BY sequence ASC"
        ).fetchall()
        return tuple(EventEnvelope.from_dict(json.loads(row[0])) for row in rows)

    def __len__(self) -> int:
        row = self._conn.execute("SELECT COUNT(*) FROM events").fetchone()
        return int(row[0]) if row is not None else 0

    def signature_states(self) -> dict[str, str]:
        rows = self._conn.execute("SELECT event_id, signature_state FROM events").fetchall()
        return {str(event_id): str(state) for event_id, state in rows}

    def signature_state_for_event(self, event_id: str) -> str | None:
        row = self._conn.execute(
            "SELECT signature_state FROM events WHERE event_id = ?",
            (event_id,),
        ).fetchone()
        if row is None:
            return None
        return str(row[0])

    def close(self) -> None:
        self._conn.close()

