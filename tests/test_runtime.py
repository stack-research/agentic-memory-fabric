import pathlib
import sys
import tempfile
import unittest

PROJECT_ROOT = pathlib.Path(__file__).resolve().parents[1]
SRC_ROOT = PROJECT_ROOT / "src"
if str(SRC_ROOT) not in sys.path:
    sys.path.insert(0, str(SRC_ROOT))

from agentic_memory_fabric.crypto import sign_event
from agentic_memory_fabric.events import EventEnvelope, canonical_payload_hash
from agentic_memory_fabric.query_index import InMemoryQueryIndex, QueryIndexEntry
from agentic_memory_fabric.replay import replay_events
from agentic_memory_fabric.runtime import MemoryRuntime, open_runtime


def _event(
    *,
    sequence: int,
    event_id: str,
    event_type: str,
    previous_events: list[str],
    tenant_id: str = "tenant-alpha",
    memory_id: str = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
    payload: object | None = None,
) -> dict:
    if payload is None:
        payload_char = format(sequence % 16, "x")
        payload_hash = "sha256:" + (payload_char * 64)
    else:
        payload_hash = canonical_payload_hash(payload)
    event = {
        "event_id": event_id,
        "sequence": sequence,
        "timestamp": {"wall_time": "2026-03-22T00:00:00Z", "tick": sequence},
        "actor": {"id": "svc-memory", "kind": "service"},
        "tenant_id": tenant_id,
        "memory_id": memory_id,
        "event_type": event_type,
        "previous_events": previous_events,
        "payload_hash": payload_hash,
    }
    if payload is not None:
        event["payload"] = payload
    return event


def _signed_event(
    *,
    sequence: int,
    event_id: str,
    event_type: str,
    previous_events: list[str],
    key_id: str = "dev-key",
    key: bytes = b"super-secret",
    payload: object | None = None,
) -> dict:
    event = EventEnvelope.from_dict(
        _event(
            sequence=sequence,
            event_id=event_id,
            event_type=event_type,
            previous_events=previous_events,
            payload=payload,
        )
    )
    event_dict = event.to_dict()
    event_dict["signature"] = {
        "alg": "hmac-sha256",
        "key_id": key_id,
        "sig": sign_event(event, key_id=key_id, key=key),
    }
    return event_dict


class RuntimeReadModelTests(unittest.TestCase):
    def test_state_map_matches_full_replay_oracle(self) -> None:
        runtime = MemoryRuntime()
        runtime.ingest_event(
            _event(
                sequence=1,
                event_id="11111111-1111-4111-8111-111111111111",
                event_type="created",
                previous_events=[],
            )
        )
        runtime.ingest_event(
            _event(
                sequence=2,
                event_id="22222222-2222-4222-8222-222222222222",
                event_type="updated",
                previous_events=["11111111-1111-4111-8111-111111111111"],
            )
        )

        oracle = replay_events(
            runtime.log.all_events(),
            signature_states=runtime.log.signature_states(),
        )
        self.assertEqual(runtime.state_map(), oracle)

    def test_repeated_reads_are_stable(self) -> None:
        runtime = open_runtime(keyring={"dev-key": b"super-secret"})
        runtime.ingest_event(
            _signed_event(
                sequence=1,
                event_id="11111111-1111-4111-8111-111111111111",
                event_type="created",
                previous_events=[],
            ),
            expected_tenant_id="tenant-alpha",
            trusted_context={"tenant_id": "tenant-alpha"},
        )

        query_one = runtime.query(
            policy_context={"tenant_id": "tenant-alpha"},
            trusted_context={"tenant_id": "tenant-alpha"},
        )
        query_two = runtime.query(
            policy_context={"tenant_id": "tenant-alpha"},
            trusted_context={"tenant_id": "tenant-alpha"},
        )
        snapshot_one = runtime.export_snapshot(
            policy_context={"tenant_id": "tenant-alpha"},
            trusted_context={"tenant_id": "tenant-alpha"},
        )
        snapshot_two = runtime.export_snapshot(
            policy_context={"tenant_id": "tenant-alpha"},
            trusted_context={"tenant_id": "tenant-alpha"},
        )

        self.assertEqual(query_one, query_two)
        self.assertTrue(query_one["query_allowed"])
        self.assertEqual(snapshot_one, snapshot_two)

    def test_cache_invalidates_after_ingest_and_import(self) -> None:
        runtime = MemoryRuntime()
        runtime.ingest_event(
            _event(
                sequence=1,
                event_id="11111111-1111-4111-8111-111111111111",
                event_type="created",
                previous_events=[],
            )
        )
        first_state = runtime.state_map()
        self.assertEqual(
            first_state["aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"].version,
            1,
        )

        runtime.ingest_event(
            _event(
                sequence=2,
                event_id="22222222-2222-4222-8222-222222222222",
                event_type="updated",
                previous_events=["11111111-1111-4111-8111-111111111111"],
            )
        )
        second_state = runtime.state_map()
        self.assertEqual(
            second_state["aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"].version,
            2,
        )

        runtime.import_records(
            [
                {
                    "memory_id": "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
                    "payload": {"v": "seed"},
                    "source_id": "seed-1",
                }
            ],
            actor={"id": "migration-bot", "kind": "service"},
            default_timestamp="2026-03-22T00:00:00Z",
            tenant_id="tenant-alpha",
        )
        after_import = runtime.state_map()
        self.assertIn("bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb", after_import)

    def test_sqlite_reopen_matches_replay_oracle(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = pathlib.Path(tmpdir) / "events.db"
            runtime = open_runtime(db_path=db_path)
            reopened = None
            try:
                runtime.ingest_event(
                    _event(
                        sequence=1,
                        event_id="11111111-1111-4111-8111-111111111111",
                        event_type="created",
                        previous_events=[],
                    )
                )
                runtime.ingest_event(
                    _event(
                        sequence=2,
                        event_id="22222222-2222-4222-8222-222222222222",
                        event_type="updated",
                        previous_events=["11111111-1111-4111-8111-111111111111"],
                    )
                )

                reopened = open_runtime(db_path=db_path)
                oracle = replay_events(
                    reopened.log.all_events(),
                    signature_states=reopened.log.signature_states(),
                )
                self.assertEqual(reopened.state_map(), oracle)
            finally:
                runtime.close()
                if reopened is not None:
                    reopened.close()

    def test_recall_appends_event_without_bumping_content_version(self) -> None:
        runtime = open_runtime(keyring={"dev-key": b"super-secret"})
        runtime.ingest_event(
            _signed_event(
                sequence=1,
                event_id="11111111-1111-4111-8111-111111111111",
                event_type="created",
                previous_events=[],
            ),
            expected_tenant_id="tenant-alpha",
            trusted_context={"tenant_id": "tenant-alpha"},
        )
        result = runtime.recall(
            "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
            actor={"id": "svc-memory", "kind": "service"},
            policy_context={"tenant_id": "tenant-alpha"},
            trusted_context={"tenant_id": "tenant-alpha"},
            event_id="22222222-2222-4222-8222-222222222222",
            timestamp={"wall_time": "2026-03-22T00:00:00Z", "tick": 9},
        )
        self.assertEqual(result["outcome"], "appended")
        self.assertEqual(result["event"]["event_type"], "recalled")
        self.assertEqual(result["record"]["version"], 1)
        self.assertEqual(result["record"]["recall_count"], 1)
        self.assertEqual(result["record"]["last_recall_tick"], 9)

    def test_reconsolidate_appends_event_and_bumps_content_version(self) -> None:
        runtime = open_runtime(keyring={"dev-key": b"super-secret"})
        runtime.ingest_event(
            _signed_event(
                sequence=1,
                event_id="11111111-1111-4111-8111-111111111111",
                event_type="created",
                previous_events=[],
            ),
            expected_tenant_id="tenant-alpha",
            trusted_context={"tenant_id": "tenant-alpha"},
        )
        result = runtime.reconsolidate(
            "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
            actor={"id": "svc-memory", "kind": "service"},
            payload_hash="sha256:" + ("b" * 64),
            policy_context={"tenant_id": "tenant-alpha"},
            trusted_context={"tenant_id": "tenant-alpha"},
            event_id="33333333-3333-4333-8333-333333333333",
            timestamp={"wall_time": "2026-03-22T00:00:00Z", "tick": 11},
        )
        self.assertEqual(result["outcome"], "appended")
        self.assertEqual(result["event"]["event_type"], "reconsolidated")
        self.assertEqual(result["record"]["version"], 2)
        self.assertEqual(result["record"]["reconsolidation_count"], 1)
        self.assertEqual(result["record"]["last_write_tick"], 11)

    def test_dynamic_event_ingest_rejects_bad_head_or_payload_rules(self) -> None:
        runtime = MemoryRuntime()
        runtime.ingest_event(
            _event(
                sequence=1,
                event_id="11111111-1111-4111-8111-111111111111",
                event_type="created",
                previous_events=[],
            )
        )
        with self.assertRaisesRegex(ValueError, "preserve the current payload_hash"):
            runtime.ingest_event(
                {
                    **_event(
                        sequence=2,
                        event_id="22222222-2222-4222-8222-222222222222",
                        event_type="recalled",
                        previous_events=["11111111-1111-4111-8111-111111111111"],
                    ),
                    "payload_hash": "sha256:" + ("b" * 64),
                }
            )

    def test_query_denies_when_uncertainty_signal_missing_or_low(self) -> None:
        runtime = open_runtime(keyring={"dev-key": b"super-secret"})
        runtime.ingest_event(
            _signed_event(
                sequence=1,
                event_id="11111111-1111-4111-8111-111111111111",
                event_type="created",
                previous_events=[],
            ),
            expected_tenant_id="tenant-alpha",
            trusted_context={"tenant_id": "tenant-alpha"},
        )
        missing = runtime.query(
            policy_context={"tenant_id": "tenant-alpha", "uncertainty_threshold": 0.8},
            trusted_context={"tenant_id": "tenant-alpha"},
        )
        self.assertFalse(missing["query_allowed"])
        self.assertEqual(missing["query_denial_reason"], "uncertainty_signal_required_default_deny")
        self.assertEqual(missing["records"], [])

        low = runtime.query(
            policy_context={
                "tenant_id": "tenant-alpha",
                "uncertainty_threshold": 0.8,
                "uncertainty_score": 0.4,
            },
            trusted_context={"tenant_id": "tenant-alpha"},
        )
        self.assertFalse(low["query_allowed"])
        self.assertEqual(low["query_denial_reason"], "uncertainty_below_threshold_default_deny")

        boundary = runtime.query(
            policy_context={
                "tenant_id": "tenant-alpha",
                "uncertainty_threshold": 0.8,
                "uncertainty_score": 0.8,
            },
            trusted_context={"tenant_id": "tenant-alpha"},
        )
        self.assertTrue(boundary["query_allowed"])
        self.assertEqual(boundary["count"], 1)

    def test_semantic_query_returns_ranked_record_for_inline_payload(self) -> None:
        runtime = open_runtime(keyring={"dev-key": b"super-secret"})
        runtime.ingest_event(
            _signed_event(
                sequence=1,
                event_id="11111111-1111-4111-8111-111111111111",
                event_type="created",
                previous_events=[],
                payload={"topic": "memory fabric", "note": "hybrid lexical baseline"},
            ),
            expected_tenant_id="tenant-alpha",
            trusted_context={"tenant_id": "tenant-alpha"},
        )
        result = runtime.query(
            policy_context={"tenant_id": "tenant-alpha"},
            trusted_context={"tenant_id": "tenant-alpha"},
            query_text="memory fabric",
        )
        self.assertEqual(result["count"], 1)
        record = result["records"][0]
        self.assertEqual(record["indexed_event_id"], "11111111-1111-4111-8111-111111111111")
        self.assertEqual(record["retrieval_mode"], "lexical_v1")
        self.assertGreater(record["retrieval_score"], 0.0)
        self.assertTrue(record["queryable_payload_present"])

    def test_semantic_query_skips_hash_only_heads_but_inventory_query_still_returns_them(self) -> None:
        runtime = open_runtime(keyring={"dev-key": b"super-secret"})
        runtime.ingest_event(
            _signed_event(
                sequence=1,
                event_id="11111111-1111-4111-8111-111111111111",
                event_type="created",
                previous_events=[],
            ),
            expected_tenant_id="tenant-alpha",
            trusted_context={"tenant_id": "tenant-alpha"},
        )
        semantic = runtime.query(
            policy_context={"tenant_id": "tenant-alpha"},
            trusted_context={"tenant_id": "tenant-alpha"},
            query_text="missing payload",
        )
        inventory = runtime.query(
            policy_context={"tenant_id": "tenant-alpha"},
            trusted_context={"tenant_id": "tenant-alpha"},
        )
        self.assertEqual(semantic["count"], 0)
        self.assertEqual(inventory["count"], 1)
        self.assertFalse(inventory["records"][0]["queryable_payload_present"])

    def test_semantic_query_discards_stale_index_entries(self) -> None:
        runtime = open_runtime(keyring={"dev-key": b"super-secret"})
        runtime.ingest_event(
            _signed_event(
                sequence=1,
                event_id="11111111-1111-4111-8111-111111111111",
                event_type="created",
                previous_events=[],
                payload={"topic": "alpha memory"},
            ),
            expected_tenant_id="tenant-alpha",
            trusted_context={"tenant_id": "tenant-alpha"},
        )
        runtime._query_index_cache = InMemoryQueryIndex(
            (
                QueryIndexEntry(
                    tenant_id="tenant-alpha",
                    memory_id="aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
                    indexed_event_id="33333333-3333-4333-8333-333333333333",
                    trust_state="trusted",
                    retrieval_text='{"topic":"alpha memory"}',
                    indexed_sequence=1,
                ),
            )
        )
        result = runtime.query(
            policy_context={"tenant_id": "tenant-alpha"},
            trusted_context={"tenant_id": "tenant-alpha"},
            query_text="alpha",
        )
        self.assertEqual(result["count"], 0)

    def test_query_override_requires_trusted_context(self) -> None:
        runtime = open_runtime(keyring={"dev-key": b"super-secret"})
        runtime.ingest_event(
            _signed_event(
                sequence=1,
                event_id="11111111-1111-4111-8111-111111111111",
                event_type="created",
                previous_events=[],
            ),
            expected_tenant_id="tenant-alpha",
            trusted_context={"tenant_id": "tenant-alpha"},
        )
        untrusted = runtime.query(
            policy_context={
                "tenant_id": "tenant-alpha",
                "uncertainty_threshold": 0.8,
                "uncertainty_score": 0.4,
                "allow_low_uncertainty_override": True,
            },
            trusted_context={"tenant_id": "tenant-alpha"},
        )
        self.assertFalse(untrusted["query_allowed"])

        trusted = runtime.query(
            policy_context={
                "tenant_id": "tenant-alpha",
                "uncertainty_threshold": 0.8,
                "uncertainty_score": 0.4,
                "allow_low_uncertainty_override": True,
            },
            trusted_context={
                "tenant_id": "tenant-alpha",
                "capabilities": ["override_retrieval_denials"],
            },
        )
        self.assertTrue(trusted["query_allowed"])
        self.assertEqual(trusted["query_denial_reason"], "uncertainty_below_threshold_default_deny")
        self.assertTrue(trusted["query_override_used"])
        with self.assertRaisesRegex(ValueError, "change the payload_hash"):
            runtime.ingest_event(
                {
                    **_event(
                        sequence=2,
                        event_id="33333333-3333-4333-8333-333333333333",
                        event_type="reconsolidated",
                        previous_events=["11111111-1111-4111-8111-111111111111"],
                    ),
                    "payload_hash": "sha256:" + ("1" * 64),
                }
            )
