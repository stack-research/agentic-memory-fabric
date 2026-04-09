"""SQLite-backed append-only event log."""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path

from .events import EventEnvelope
from .log import PendingQuerySync, QuerySyncTask, SignatureVerifier


def _table_column_names(conn: sqlite3.Connection, table: str) -> set[str]:
    rows = conn.execute(f"PRAGMA table_info({table})").fetchall()
    return {str(row[1]) for row in rows}


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
        self._migrate_lineage_columns()
        self._conn.commit()

    def _migrate_lineage_columns(self) -> None:
        names = _table_column_names(self._conn, "events")
        if "memory_id" not in names:
            self._conn.execute("ALTER TABLE events ADD COLUMN memory_id TEXT")
            self._conn.execute("ALTER TABLE events ADD COLUMN tenant_id TEXT")
            self._conn.execute(
                """
                UPDATE events SET
                    memory_id = json_extract(event_json, '$.memory_id'),
                    tenant_id = json_extract(event_json, '$.tenant_id')
                WHERE memory_id IS NULL OR tenant_id IS NULL
                """
            )
        self._conn.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_events_tenant_memory_seq
            ON events(tenant_id, memory_id, sequence)
            """
        )

    def append(
        self,
        event: EventEnvelope,
        *,
        signature_verifier: SignatureVerifier | None = None,
        query_sync_tasks: tuple[QuerySyncTask, ...] | None = None,
    ) -> None:
        del query_sync_tasks
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
            """
            INSERT INTO events (
                sequence, event_id, event_json, signature_state, memory_id, tenant_id
            ) VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                event.sequence,
                event.event_id,
                json.dumps(event.to_dict(), sort_keys=True),
                signature_state,
                event.memory_id,
                event.tenant_id,
            ),
        )
        self._conn.commit()

    def all_events(self) -> tuple[EventEnvelope, ...]:
        rows = self._conn.execute(
            "SELECT event_json FROM events ORDER BY sequence ASC"
        ).fetchall()
        return tuple(EventEnvelope.from_dict(json.loads(row[0])) for row in rows)

    def all_events_with_signature_states(self) -> tuple[tuple[EventEnvelope, ...], dict[str, str]]:
        rows = self._conn.execute(
            "SELECT event_json, event_id, signature_state FROM events ORDER BY sequence ASC"
        ).fetchall()
        events: list[EventEnvelope] = []
        signature_states: dict[str, str] = {}
        for event_json, event_id, signature_state in rows:
            events.append(EventEnvelope.from_dict(json.loads(event_json)))
            signature_states[str(event_id)] = str(signature_state)
        return tuple(events), signature_states

    def events_in_sequence_range(self, *, start: int, end: int) -> tuple[EventEnvelope, ...]:
        if start < 1 or end < start:
            raise ValueError("sequence range must be (start>=1, end>=start)")
        rows = self._conn.execute(
            """
            SELECT event_json
            FROM events
            WHERE sequence BETWEEN ? AND ?
            ORDER BY sequence ASC
            """,
            (start, end),
        ).fetchall()
        return tuple(EventEnvelope.from_dict(json.loads(row[0])) for row in rows)

    def events_for_memory(
        self,
        memory_id: str,
        tenant_id: str | None,
    ) -> tuple[EventEnvelope, ...]:
        if tenant_id is not None:
            rows = self._conn.execute(
                """
                SELECT event_json
                FROM events
                WHERE memory_id = ? AND tenant_id = ?
                ORDER BY sequence ASC
                """,
                (memory_id, tenant_id),
            ).fetchall()
        else:
            rows = self._conn.execute(
                """
                SELECT event_json
                FROM events
                WHERE memory_id = ?
                ORDER BY sequence ASC
                """,
                (memory_id,),
            ).fetchall()
        return tuple(EventEnvelope.from_dict(json.loads(row[0])) for row in rows)

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
        if tenant_id is not None:
            rows = self._conn.execute(
                """
                SELECT event_json
                FROM events
                WHERE memory_id = ? AND tenant_id = ? AND sequence BETWEEN ? AND ?
                ORDER BY sequence ASC
                """,
                (memory_id, tenant_id, start, end),
            ).fetchall()
        else:
            rows = self._conn.execute(
                """
                SELECT event_json
                FROM events
                WHERE memory_id = ? AND sequence BETWEEN ? AND ?
                ORDER BY sequence ASC
                """,
                (memory_id, start, end),
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

    def pending_query_sync(self, *, limit: int | None = None) -> tuple[PendingQuerySync, ...]:
        del limit
        return ()

    def mark_query_sync_processed(self, row_ids: tuple[int, ...]) -> None:
        del row_ids
        return

    def query_sync_lag_count(self) -> int:
        return 0
