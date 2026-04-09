"""Postgres-backed append-only event log with durable query-sync outbox."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .events import EventEnvelope
from .log import PendingQuerySync, QuerySyncTask, SignatureVerifier
from .postgres_support import PostgresBackendError, load_postgres_driver, quote_identifier


EVENTS_TABLE = "events"
OUTBOX_TABLE = "query_sync_outbox"


class PostgresEventLog:
    def __init__(
        self,
        dsn: str | Path,
        *,
        schema: str = "amf_core",
        bootstrap: bool = False,
    ) -> None:
        dsn_text = str(dsn).strip()
        if not dsn_text:
            raise ValueError("event_backend_dsn is required for postgres")
        self._dsn = dsn_text
        self._driver, self._driver_name = load_postgres_driver()
        self._schema = schema
        self._schema_sql = quote_identifier(schema, field_name="event backend schema")
        self._events_table_sql = f"{self._schema_sql}.{EVENTS_TABLE}"
        self._outbox_table_sql = f"{self._schema_sql}.{OUTBOX_TABLE}"
        self._connect()
        if bootstrap:
            self._bootstrap_schema()

    def _connect(self) -> None:
        try:
            self._conn = self._driver.connect(self._dsn)
            if hasattr(self._conn, "autocommit"):
                self._conn.autocommit = False
        except Exception as exc:  # pragma: no cover - depends on environment
            raise PostgresBackendError(f"unable to connect to Postgres event backend: {exc}") from exc

    def _execute(
        self,
        sql: str,
        params: tuple[Any, ...] = (),
        *,
        fetch: bool = False,
    ) -> Any:
        cursor = None
        try:
            cursor = self._conn.cursor()
            cursor.execute(sql, params)
            if fetch:
                return cursor.fetchall()
            return None
        except Exception as exc:  # pragma: no cover - depends on environment
            self._conn.rollback()
            raise PostgresBackendError(f"Postgres event backend query failed: {exc}") from exc
        finally:
            if cursor is not None:
                cursor.close()

    def _bootstrap_schema(self) -> None:
        cursor = None
        try:
            cursor = self._conn.cursor()
            cursor.execute(f"CREATE SCHEMA IF NOT EXISTS {self._schema_sql}")
            cursor.execute(
                f"""
                CREATE TABLE IF NOT EXISTS {self._events_table_sql} (
                    sequence BIGINT PRIMARY KEY,
                    event_id TEXT NOT NULL UNIQUE,
                    tenant_id TEXT NOT NULL,
                    memory_id TEXT NOT NULL,
                    event_json JSONB NOT NULL,
                    signature_state TEXT NOT NULL,
                    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
                )
                """
            )
            cursor.execute(
                f"""
                CREATE INDEX IF NOT EXISTS idx_events_tenant_memory_seq
                ON {self._events_table_sql}(tenant_id, memory_id, sequence)
                """
            )
            cursor.execute(
                f"""
                CREATE INDEX IF NOT EXISTS idx_events_tenant_seq
                ON {self._events_table_sql}(tenant_id, sequence)
                """
            )
            cursor.execute(
                f"""
                CREATE TABLE IF NOT EXISTS {self._outbox_table_sql} (
                    id BIGSERIAL PRIMARY KEY,
                    tenant_id TEXT NOT NULL,
                    memory_id TEXT NOT NULL,
                    indexed_event_id TEXT NOT NULL,
                    reason TEXT NOT NULL,
                    processed_at TIMESTAMPTZ NULL,
                    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
                )
                """
            )
            cursor.execute(
                f"""
                CREATE INDEX IF NOT EXISTS idx_query_sync_outbox_pending
                ON {self._outbox_table_sql}(processed_at, tenant_id, memory_id, id)
                """
            )
            self._conn.commit()
        except Exception as exc:  # pragma: no cover - depends on environment
            self._conn.rollback()
            raise PostgresBackendError(f"unable to bootstrap Postgres event backend: {exc}") from exc
        finally:
            if cursor is not None:
                cursor.close()

    def append(
        self,
        event: EventEnvelope,
        *,
        signature_verifier: SignatureVerifier | None = None,
        query_sync_tasks: tuple[QuerySyncTask, ...] | None = None,
    ) -> None:
        expected_sequence = len(self) + 1
        if event.sequence != expected_sequence:
            raise ValueError(
                f"event sequence must be contiguous; expected {expected_sequence}, got {event.sequence}"
            )
        signature_state = (
            signature_verifier(event)
            if signature_verifier is not None
            else ("unsigned" if event.signature is None else "invalid")
        )
        cursor = None
        try:
            cursor = self._conn.cursor()
            cursor.execute(
                f"""
                INSERT INTO {self._events_table_sql} (
                    sequence, event_id, tenant_id, memory_id, event_json, signature_state
                ) VALUES (%s, %s, %s, %s, %s::jsonb, %s)
                """,
                (
                    event.sequence,
                    event.event_id,
                    event.tenant_id,
                    event.memory_id,
                    json.dumps(event.to_dict(), sort_keys=True),
                    signature_state,
                ),
            )
            for task in query_sync_tasks or ():
                cursor.execute(
                    f"""
                    INSERT INTO {self._outbox_table_sql} (
                        tenant_id, memory_id, indexed_event_id, reason
                    ) VALUES (%s, %s, %s, %s)
                    """,
                    (task.tenant_id, task.memory_id, task.indexed_event_id, task.reason),
                )
            self._conn.commit()
        except Exception as exc:
            self._conn.rollback()
            if "duplicate" in str(exc).lower() or "unique" in str(exc).lower():
                raise ValueError(f"duplicate event_id: {event.event_id}") from exc
            raise PostgresBackendError(f"unable to append event in Postgres backend: {exc}") from exc
        finally:
            if cursor is not None:
                cursor.close()

    def all_events(self) -> tuple[EventEnvelope, ...]:
        rows = self._execute(
            f"SELECT event_json FROM {self._events_table_sql} ORDER BY sequence ASC",
            fetch=True,
        )
        return tuple(EventEnvelope.from_dict(self._decode_event_json(row[0])) for row in rows)

    def all_events_with_signature_states(self) -> tuple[tuple[EventEnvelope, ...], dict[str, str]]:
        rows = self._execute(
            f"""
            SELECT event_json, event_id, signature_state
            FROM {self._events_table_sql}
            ORDER BY sequence ASC
            """,
            fetch=True,
        )
        events: list[EventEnvelope] = []
        signature_states: dict[str, str] = {}
        for event_json, event_id, signature_state in rows:
            events.append(EventEnvelope.from_dict(self._decode_event_json(event_json)))
            signature_states[str(event_id)] = str(signature_state)
        return tuple(events), signature_states

    def events_in_sequence_range(self, *, start: int, end: int) -> tuple[EventEnvelope, ...]:
        if start < 1 or end < start:
            raise ValueError("sequence range must be (start>=1, end>=start)")
        rows = self._execute(
            f"""
            SELECT event_json
            FROM {self._events_table_sql}
            WHERE sequence BETWEEN %s AND %s
            ORDER BY sequence ASC
            """,
            (start, end),
            fetch=True,
        )
        return tuple(EventEnvelope.from_dict(self._decode_event_json(row[0])) for row in rows)

    def events_for_memory(
        self,
        memory_id: str,
        tenant_id: str | None,
    ) -> tuple[EventEnvelope, ...]:
        if tenant_id is not None:
            rows = self._execute(
                f"""
                SELECT event_json
                FROM {self._events_table_sql}
                WHERE memory_id = %s AND tenant_id = %s
                ORDER BY sequence ASC
                """,
                (memory_id, tenant_id),
                fetch=True,
            )
        else:
            rows = self._execute(
                f"""
                SELECT event_json
                FROM {self._events_table_sql}
                WHERE memory_id = %s
                ORDER BY sequence ASC
                """,
                (memory_id,),
                fetch=True,
            )
        return tuple(EventEnvelope.from_dict(self._decode_event_json(row[0])) for row in rows)

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
            rows = self._execute(
                f"""
                SELECT event_json
                FROM {self._events_table_sql}
                WHERE memory_id = %s AND tenant_id = %s AND sequence BETWEEN %s AND %s
                ORDER BY sequence ASC
                """,
                (memory_id, tenant_id, start, end),
                fetch=True,
            )
        else:
            rows = self._execute(
                f"""
                SELECT event_json
                FROM {self._events_table_sql}
                WHERE memory_id = %s AND sequence BETWEEN %s AND %s
                ORDER BY sequence ASC
                """,
                (memory_id, start, end),
                fetch=True,
            )
        return tuple(EventEnvelope.from_dict(self._decode_event_json(row[0])) for row in rows)

    def __len__(self) -> int:
        row = self._execute(
            f"SELECT COUNT(*) FROM {self._events_table_sql}",
            fetch=True,
        )
        return int(row[0][0]) if row else 0

    def signature_states(self) -> dict[str, str]:
        rows = self._execute(
            f"SELECT event_id, signature_state FROM {self._events_table_sql}",
            fetch=True,
        )
        return {str(event_id): str(state) for event_id, state in rows}

    def signature_state_for_event(self, event_id: str) -> str | None:
        rows = self._execute(
            f"SELECT signature_state FROM {self._events_table_sql} WHERE event_id = %s",
            (event_id,),
            fetch=True,
        )
        if not rows:
            return None
        return str(rows[0][0])

    def pending_query_sync(self, *, limit: int | None = None) -> tuple[PendingQuerySync, ...]:
        sql = (
            f"""
            SELECT id, tenant_id, memory_id, indexed_event_id, reason
            FROM {self._outbox_table_sql}
            WHERE processed_at IS NULL
            ORDER BY id ASC
            """
        )
        params: tuple[Any, ...] = ()
        if limit is not None:
            sql += " LIMIT %s"
            params = (limit,)
        rows = self._execute(sql, params, fetch=True)
        return tuple(
            PendingQuerySync(
                id=int(row[0]),
                tenant_id=str(row[1]),
                memory_id=str(row[2]),
                indexed_event_id=str(row[3]),
                reason=str(row[4]),
            )
            for row in rows
        )

    def mark_query_sync_processed(self, row_ids: tuple[int, ...]) -> None:
        if not row_ids:
            return
        cursor = None
        try:
            cursor = self._conn.cursor()
            cursor.execute(
                f"""
                UPDATE {self._outbox_table_sql}
                SET processed_at = now()
                WHERE processed_at IS NULL AND id = ANY(%s)
                """,
                (list(row_ids),),
            )
            self._conn.commit()
        except Exception as exc:  # pragma: no cover - depends on environment
            self._conn.rollback()
            raise PostgresBackendError(f"unable to mark query sync rows processed: {exc}") from exc
        finally:
            if cursor is not None:
                cursor.close()

    def query_sync_lag_count(self) -> int:
        rows = self._execute(
            f"SELECT COUNT(*) FROM {self._outbox_table_sql} WHERE processed_at IS NULL",
            fetch=True,
        )
        return int(rows[0][0]) if rows else 0

    def close(self) -> None:
        self._conn.close()

    def _decode_event_json(self, raw: Any) -> dict[str, Any]:
        if isinstance(raw, dict):
            return dict(raw)
        if isinstance(raw, str):
            return json.loads(raw)
        return dict(raw)
