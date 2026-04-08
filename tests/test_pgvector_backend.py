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
from agentic_memory_fabric.query_index import DeterministicTextEmbedder
from agentic_memory_fabric.runtime import open_runtime


def _pgvector_env_ready() -> bool:
    dsn = os.environ.get("AMF_PGVECTOR_DSN")
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


@unittest.skipUnless(_pgvector_env_ready(), "pgvector integration env not configured")
class PgVectorBackendIntegrationTests(unittest.TestCase):
    def test_pgvector_runtime_bootstraps_and_queries_current_heads(self) -> None:
        schema = "amf_test_" + uuid4().hex[:8]
        runtime = open_runtime(
            query_backend="pgvector",
            query_backend_dsn=os.environ["AMF_PGVECTOR_DSN"],
            query_backend_schema=schema,
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
        self.assertTrue(result["query_allowed"])
        self.assertEqual(result["query_backend"], "pgvector")
        self.assertEqual(result["count"], 1)
        self.assertGreater(result["candidate_count"], 0)
