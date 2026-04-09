import os
import pathlib
import sys
import unittest
from uuid import uuid4

PROJECT_ROOT = pathlib.Path(__file__).resolve().parents[1]
SRC_ROOT = PROJECT_ROOT / "src"
if str(SRC_ROOT) not in sys.path:
    sys.path.insert(0, str(SRC_ROOT))

from agentic_memory_fabric.events import canonical_payload_hash
from agentic_memory_fabric.postgres_store import PostgresEventLog
from agentic_memory_fabric.query_index import DeterministicTextEmbedder
from agentic_memory_fabric.runtime import open_runtime


def _postgres_env_ready() -> bool:
    dsn = os.environ.get("AMF_POSTGRES_DSN") or os.environ.get("AMF_PGVECTOR_DSN")
    if not dsn:
        return False
    try:
        import psycopg  # type: ignore  # noqa: F401

        return True
    except ModuleNotFoundError:
        try:
            import psycopg2  # type: ignore  # noqa: F401

            return True
        except ModuleNotFoundError:
            return False


@unittest.skipUnless(_postgres_env_ready(), "Postgres integration env not configured")
class PostgresEventBackendIntegrationTests(unittest.TestCase):
    def test_postgres_event_log_bootstrap_and_scoped_reads(self) -> None:
        schema = "amf_core_test_" + uuid4().hex[:8]
        log = PostgresEventLog(
            os.environ.get("AMF_POSTGRES_DSN") or os.environ["AMF_PGVECTOR_DSN"],
            schema=schema,
            bootstrap=True,
        )
        try:
            first = {
                "event_id": str(uuid4()),
                "sequence": 1,
                "timestamp": {"wall_time": "2026-04-08T00:00:00Z", "tick": 1},
                "actor": {"id": "svc-memory", "kind": "service"},
                "tenant_id": "tenant-alpha",
                "memory_id": "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
                "event_type": "created",
                "previous_events": [],
                "payload_hash": canonical_payload_hash({"topic": "alpha"}),
                "payload": {"topic": "alpha"},
            }
            second = {
                "event_id": str(uuid4()),
                "sequence": 2,
                "timestamp": {"wall_time": "2026-04-08T00:00:01Z", "tick": 2},
                "actor": {"id": "svc-memory", "kind": "service"},
                "tenant_id": "tenant-alpha",
                "memory_id": "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
                "event_type": "created",
                "previous_events": [],
                "payload_hash": canonical_payload_hash({"topic": "bravo"}),
                "payload": {"topic": "bravo"},
            }
            from agentic_memory_fabric.events import EventEnvelope

            log.append(EventEnvelope.from_dict(first))
            log.append(EventEnvelope.from_dict(second))
            scoped = log.events_for_memory("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", "tenant-alpha")
            self.assertEqual(len(scoped), 1)
            self.assertEqual(scoped[0].event_id, first["event_id"])
        finally:
            log.close()

    def test_runtime_postgres_events_and_pgvector_query_round_trip(self) -> None:
        dsn = os.environ.get("AMF_POSTGRES_DSN") or os.environ["AMF_PGVECTOR_DSN"]
        event_schema = "amf_core_test_" + uuid4().hex[:8]
        query_schema = "amf_query_test_" + uuid4().hex[:8]
        runtime = open_runtime(
            event_backend="postgres",
            event_backend_dsn=dsn,
            event_backend_schema=event_schema,
            bootstrap_event_backend=True,
            query_backend="pgvector",
            query_backend_dsn=dsn,
            query_backend_schema=query_schema,
            bootstrap_query_backend=True,
            embedder=DeterministicTextEmbedder(),
        )
        try:
            runtime.ingest_event(
                {
                    "event_id": str(uuid4()),
                    "sequence": 1,
                    "timestamp": {"wall_time": "2026-04-08T00:00:00Z", "tick": 1},
                    "actor": {"id": "svc-memory", "kind": "service"},
                    "tenant_id": "tenant-alpha",
                    "memory_id": "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
                    "event_type": "created",
                    "previous_events": [],
                    "payload": {"topic": "alpha memory"},
                    "payload_hash": canonical_payload_hash({"topic": "alpha memory"}),
                },
                expected_tenant_id="tenant-alpha",
                trusted_context={"tenant_id": "tenant-alpha"},
            )
            result = runtime.query(
                policy_context={"tenant_id": "tenant-alpha"},
                trusted_context={"tenant_id": "tenant-alpha"},
                query_text="alpha",
            )
        finally:
            runtime.close()
        self.assertEqual(result["count"], 1)
        self.assertEqual(result["query_backend"], "pgvector")
