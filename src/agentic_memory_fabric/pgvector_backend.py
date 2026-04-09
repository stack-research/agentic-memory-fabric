"""Postgres + pgvector semantic query backend."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping

from .postgres_support import PostgresBackendError, load_postgres_driver, quote_identifier
from .query_index import QueryBackendError, SearchHit, TextEmbedder


QUERY_INDEX_TABLE = "query_index"


def _vector_literal(values: list[float]) -> str:
    return "[" + ",".join(f"{value:.6f}" for value in values) + "]"


@dataclass(frozen=True)
class PgVectorBackendConfig:
    dsn: str
    schema: str = "amf_query"
    bootstrap: bool = False


class PgVectorQueryBackend:
    name = "pgvector"

    def __init__(
        self,
        *,
        dsn: str,
        schema: str = "amf_query",
        embedder: TextEmbedder,
        bootstrap: bool = False,
    ) -> None:
        if not dsn.strip():
            raise ValueError("query_backend_dsn is required for pgvector")
        self._dsn = dsn
        self._schema = schema
        self._embedder = embedder
        self._bootstrap = bootstrap
        try:
            self._driver, self._driver_name = load_postgres_driver()
        except PostgresBackendError as exc:
            raise QueryBackendError(str(exc)) from exc
        self._schema_sql = quote_identifier(schema, field_name="query backend schema")
        self._table_sql = f"{self._schema_sql}.{QUERY_INDEX_TABLE}"
        self._connect()
        if bootstrap:
            self._bootstrap_schema()

    def _connect(self) -> None:
        try:
            self._conn = self._driver.connect(self._dsn)
            if hasattr(self._conn, "autocommit"):
                self._conn.autocommit = True
        except Exception as exc:  # pragma: no cover - depends on environment
            raise QueryBackendError(f"unable to connect to pgvector backend: {exc}") from exc

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
            raise QueryBackendError(f"pgvector backend query failed: {exc}") from exc
        finally:
            if cursor is not None:
                cursor.close()

    def _bootstrap_schema(self) -> None:
        self._execute("CREATE EXTENSION IF NOT EXISTS vector")
        self._execute(f"CREATE SCHEMA IF NOT EXISTS {self._schema_sql}")
        self._execute(
            f"""
            CREATE TABLE IF NOT EXISTS {self._table_sql} (
                tenant_id TEXT NOT NULL,
                memory_id TEXT PRIMARY KEY,
                indexed_event_id TEXT NOT NULL,
                memory_class TEXT NOT NULL,
                trust_state TEXT NOT NULL,
                lifecycle_state TEXT NOT NULL,
                signature_state TEXT NOT NULL,
                queryable_payload_present BOOLEAN NOT NULL,
                retrieval_text TEXT NOT NULL,
                embedding vector({self._embedder.dimension}) NOT NULL,
                updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
            )
            """
        )
        self._execute(
            f"""
            CREATE INDEX IF NOT EXISTS idx_query_index_tenant_labels
            ON {self._table_sql}(tenant_id, memory_class, trust_state, lifecycle_state)
            """
        )
        self._execute(
            f"""
            CREATE INDEX IF NOT EXISTS idx_query_index_embedding_hnsw
            ON {self._table_sql} USING hnsw (embedding vector_cosine_ops)
            """
        )

    def search(
        self,
        *,
        query_text: str,
        tenant_id: str | None,
        memory_class: str | None = None,
        limit: int | None = None,
    ) -> list[SearchHit]:
        if tenant_id is None:
            return []
        if limit is not None and limit < 1:
            raise ValueError("limit must be >= 1 when provided")
        embedding = _vector_literal(self._embedder.embed_text(query_text))
        sql = (
            f"SELECT tenant_id, memory_id, indexed_event_id, "
            f"ROUND((1 - (embedding <=> %s::vector))::numeric, 6) AS score "
            f"FROM {self._table_sql} "
            f"WHERE tenant_id = %s"
        )
        params: list[Any] = [embedding, tenant_id]
        if memory_class is not None:
            sql += " AND memory_class = %s"
            params.append(memory_class)
        sql += " ORDER BY embedding <=> %s::vector, memory_id, indexed_event_id"
        params.append(embedding)
        if limit is not None:
            sql += " LIMIT %s"
            params.append(limit)
        rows = self._execute(sql, tuple(params), fetch=True)
        return [
            SearchHit(
                tenant_id=str(row[0]),
                memory_id=str(row[1]),
                indexed_event_id=str(row[2]),
                retrieval_score=float(row[3]),
                retrieval_mode="pgvector_v1",
            )
            for row in rows
        ]

    def refresh(
        self,
        state_map: Mapping[str, Any],
        *,
        memory_ids: tuple[str, ...] | None = None,
    ) -> None:
        if memory_ids is None:
            self._execute(f"DELETE FROM {self._table_sql}")
            target_ids = tuple(sorted(state_map))
        else:
            target_ids = tuple(dict.fromkeys(memory_ids))
        for memory_id in target_ids:
            state = state_map.get(memory_id)
            if (
                state is None
                or not state.queryable_payload_present
                or not state.retrieval_text
            ):
                self._execute(f"DELETE FROM {self._table_sql} WHERE memory_id = %s", (memory_id,))
                continue
            embedding = _vector_literal(self._embedder.embed_text(state.retrieval_text))
            self._execute(
                f"""
                INSERT INTO {self._table_sql} (
                    tenant_id,
                    memory_id,
                    indexed_event_id,
                    memory_class,
                    trust_state,
                    lifecycle_state,
                    signature_state,
                    queryable_payload_present,
                    retrieval_text,
                    embedding,
                    updated_at
                ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s::vector, now())
                ON CONFLICT (memory_id) DO UPDATE SET
                    tenant_id = EXCLUDED.tenant_id,
                    indexed_event_id = EXCLUDED.indexed_event_id,
                    memory_class = EXCLUDED.memory_class,
                    trust_state = EXCLUDED.trust_state,
                    lifecycle_state = EXCLUDED.lifecycle_state,
                    signature_state = EXCLUDED.signature_state,
                    queryable_payload_present = EXCLUDED.queryable_payload_present,
                    retrieval_text = EXCLUDED.retrieval_text,
                    embedding = EXCLUDED.embedding,
                    updated_at = now()
                """,
                (
                    state.tenant_id,
                    state.memory_id,
                    state.last_event_id,
                    state.memory_class,
                    state.trust_state,
                    state.lifecycle_state,
                    state.signature_state,
                    state.queryable_payload_present,
                    state.retrieval_text,
                    embedding,
                ),
            )

    def close(self) -> None:
        try:
            self._conn.close()
        except Exception:  # pragma: no cover - depends on environment
            return
