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
    memory_class: str | None = None,
    promoted_from_memory_ids: list[str] | None = None,
    promoted_from_event_ids: list[str] | None = None,
    target_memory_id: str | None = None,
    edge_weight: float | None = None,
    edge_reason: str | None = None,
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
    if memory_class is not None:
        event["memory_class"] = memory_class
    if promoted_from_memory_ids is not None:
        event["promoted_from_memory_ids"] = promoted_from_memory_ids
    if promoted_from_event_ids is not None:
        event["promoted_from_event_ids"] = promoted_from_event_ids
    if target_memory_id is not None:
        event["target_memory_id"] = target_memory_id
    if edge_weight is not None:
        event["edge_weight"] = edge_weight
    if edge_reason is not None:
        event["edge_reason"] = edge_reason
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
    memory_id: str = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
    memory_class: str | None = None,
) -> dict:
    event = EventEnvelope.from_dict(
        _event(
            sequence=sequence,
            event_id=event_id,
            event_type=event_type,
            previous_events=previous_events,
            memory_id=memory_id,
            payload=payload,
            memory_class=memory_class,
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

    def test_assess_promotion_returns_score_and_default_eligibility_for_signed_episodic_memory(self) -> None:
        runtime = open_runtime(keyring={"dev-key": b"super-secret"})
        runtime.ingest_event(
            _signed_event(
                sequence=1,
                event_id="11111111-1111-4111-8111-111111111111",
                event_type="created",
                previous_events=[],
                payload={"topic": "episodic alpha"},
            ),
            expected_tenant_id="tenant-alpha",
            trusted_context={"tenant_id": "tenant-alpha"},
        )
        runtime.recall(
            "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
            actor={"id": "svc-memory", "kind": "service"},
            policy_context={"tenant_id": "tenant-alpha"},
            trusted_context={"tenant_id": "tenant-alpha"},
            event_id="22222222-2222-4222-8222-222222222222",
            timestamp={"wall_time": "2026-03-22T00:00:00Z", "tick": 5},
        )
        assessment = runtime.assess_promotion(
            "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
            policy_context={"tenant_id": "tenant-alpha"},
            trusted_context={"tenant_id": "tenant-alpha"},
        )
        self.assertEqual(assessment["memory_class"], "episodic")
        self.assertTrue(assessment["promotion_eligible"])
        self.assertGreater(assessment["promotion_score"], 0.0)
        self.assertIsNone(assessment["denial_reason"])

    def test_assess_promotion_denies_cross_tenant_and_semantic_memories(self) -> None:
        runtime = open_runtime(keyring={"dev-key": b"super-secret"})
        runtime.ingest_event(
            _signed_event(
                sequence=1,
                event_id="11111111-1111-4111-8111-111111111111",
                event_type="created",
                previous_events=[],
                payload={"topic": "episodic alpha"},
            ),
            expected_tenant_id="tenant-alpha",
            trusted_context={"tenant_id": "tenant-alpha"},
        )
        cross_tenant = runtime.assess_promotion(
            "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
            policy_context={"tenant_id": "tenant-bravo"},
            trusted_context={"tenant_id": "tenant-bravo"},
        )
        self.assertFalse(cross_tenant["promotion_eligible"])
        self.assertEqual(cross_tenant["denial_reason"], "tenant_scope_mismatch_default_deny")

        promoted = runtime.promote(
            ["aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"],
            actor={"id": "auditor", "kind": "service"},
            payload={"topic": "semantic alpha"},
            policy_context={"tenant_id": "tenant-alpha"},
            trusted_context={
                "tenant_id": "tenant-alpha",
                "capabilities": ["override_retrieval_denials"],
            },
            promoted_memory_id="bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
            event_id="33333333-3333-4333-8333-333333333333",
            timestamp={"wall_time": "2026-03-22T00:00:00Z", "tick": 6},
        )
        self.assertEqual(promoted["outcome"], "appended")
        semantic_assessment = runtime.assess_promotion(
            "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
            policy_context={"tenant_id": "tenant-alpha"},
            trusted_context={
                "tenant_id": "tenant-alpha",
                "capabilities": ["override_retrieval_denials"],
            },
        )
        self.assertFalse(semantic_assessment["promotion_eligible"])
        self.assertEqual(semantic_assessment["denial_reason"], "memory_class_not_promotable")

    def test_promote_creates_new_semantic_memory_with_lineage_links(self) -> None:
        runtime = open_runtime(keyring={"dev-key": b"super-secret"})
        runtime.ingest_event(
            _signed_event(
                sequence=1,
                event_id="11111111-1111-4111-8111-111111111111",
                event_type="created",
                previous_events=[],
                payload={"topic": "episodic alpha"},
            ),
            expected_tenant_id="tenant-alpha",
            trusted_context={"tenant_id": "tenant-alpha"},
        )
        result = runtime.promote(
            ["aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"],
            actor={"id": "auditor", "kind": "service"},
            payload={"topic": "semantic alpha"},
            policy_context={"tenant_id": "tenant-alpha"},
            trusted_context={
                "tenant_id": "tenant-alpha",
                "capabilities": ["override_retrieval_denials"],
            },
            promoted_memory_id="bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
            event_id="22222222-2222-4222-8222-222222222222",
            timestamp={"wall_time": "2026-03-22T00:00:00Z", "tick": 2},
        )
        self.assertEqual(result["outcome"], "appended")
        self.assertEqual(result["promoted_memory_id"], "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb")
        self.assertEqual(result["event"]["event_type"], "promoted")
        self.assertEqual(result["event"]["memory_class"], "semantic")
        state_map = runtime.state_map()
        self.assertEqual(state_map["aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"].memory_class, "episodic")
        promoted_state = state_map["bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"]
        self.assertEqual(promoted_state.memory_class, "semantic")
        self.assertEqual(
            promoted_state.promoted_from_memory_ids,
            ("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",),
        )

    def test_promote_multi_source_requires_all_sources_to_be_eligible(self) -> None:
        runtime = open_runtime(keyring={"dev-key": b"super-secret"})
        runtime.ingest_event(
            _signed_event(
                sequence=1,
                event_id="11111111-1111-4111-8111-111111111111",
                event_type="created",
                previous_events=[],
                payload={"topic": "episodic alpha"},
            ),
            expected_tenant_id="tenant-alpha",
            trusted_context={"tenant_id": "tenant-alpha"},
        )
        runtime.ingest_event(
            _event(
                sequence=2,
                event_id="22222222-2222-4222-8222-222222222222",
                event_type="created",
                previous_events=[],
                memory_id="bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
                payload={"topic": "unsigned bravo"},
            )
        )
        denied = runtime.promote(
            [
                "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
                "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
            ],
            actor={"id": "svc-memory", "kind": "service"},
            payload={"topic": "semantic combined"},
            policy_context={"tenant_id": "tenant-alpha"},
            trusted_context={"tenant_id": "tenant-alpha"},
            promoted_memory_id="cccccccc-cccc-4ccc-8ccc-cccccccccccc",
            event_id="33333333-3333-4333-8333-333333333333",
            timestamp={"wall_time": "2026-03-22T00:00:00Z", "tick": 3},
        )
        self.assertEqual(denied["outcome"], "denied")
        self.assertIn("bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb", denied["source_denials"])

        allowed = runtime.promote(
            [
                "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
                "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
            ],
            actor={"id": "auditor", "kind": "service"},
            payload={"topic": "semantic combined"},
            policy_context={"tenant_id": "tenant-alpha"},
            trusted_context={
                "tenant_id": "tenant-alpha",
                "capabilities": ["override_retrieval_denials"],
            },
            promoted_memory_id="dddddddd-dddd-4ddd-8ddd-dddddddddddd",
            event_id="44444444-4444-4444-8444-444444444444",
            timestamp={"wall_time": "2026-03-22T00:00:00Z", "tick": 4},
        )
        self.assertEqual(allowed["outcome"], "appended")
        semantic_query = runtime.query(
            policy_context={"tenant_id": "tenant-alpha"},
            trusted_context={
                "tenant_id": "tenant-alpha",
                "capabilities": ["override_retrieval_denials"],
            },
            structured_filter={"memory_class": "semantic"},
        )
        self.assertEqual(semantic_query["count"], 1)
        self.assertEqual(semantic_query["records"][0]["memory_class"], "semantic")
        self.assertIn(
            "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
            semantic_query["records"][0]["promoted_from_memory_ids"],
        )

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

    def test_link_reinforce_and_conflict_append_graph_events(self) -> None:
        runtime = open_runtime(keyring={"dev-key": b"super-secret"})
        source = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
        target = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
        runtime.ingest_event(
            _signed_event(
                sequence=1,
                event_id="11111111-1111-4111-8111-111111111111",
                event_type="created",
                previous_events=[],
                payload={"topic": "alpha"},
                memory_id=source,
            ),
            expected_tenant_id="tenant-alpha",
            trusted_context={"tenant_id": "tenant-alpha"},
        )
        runtime.ingest_event(
            _signed_event(
                sequence=2,
                event_id="22222222-2222-4222-8222-222222222222",
                event_type="created",
                previous_events=[],
                payload={"topic": "bravo"},
                memory_id=target,
            ),
            expected_tenant_id="tenant-alpha",
            trusted_context={"tenant_id": "tenant-alpha"},
        )
        linked = runtime.link(
            source,
            target,
            actor={"id": "svc-memory", "kind": "service"},
            policy_context={"tenant_id": "tenant-alpha"},
            trusted_context={"tenant_id": "tenant-alpha"},
            event_id="33333333-3333-4333-8333-333333333333",
            timestamp={"wall_time": "2026-03-22T00:00:00Z", "tick": 3},
        )
        reinforced = runtime.reinforce(
            source,
            actor={"id": "svc-memory", "kind": "service"},
            related_memory_id=target,
            policy_context={"tenant_id": "tenant-alpha"},
            trusted_context={"tenant_id": "tenant-alpha"},
            event_id="44444444-4444-4444-8444-444444444444",
            timestamp={"wall_time": "2026-03-22T00:00:00Z", "tick": 4},
            edge_weight=2.0,
        )
        conflicted = runtime.conflict(
            source,
            target,
            actor={"id": "svc-memory", "kind": "service"},
            policy_context={"tenant_id": "tenant-alpha"},
            trusted_context={"tenant_id": "tenant-alpha"},
            event_id="55555555-5555-4555-8555-555555555555",
            timestamp={"wall_time": "2026-03-22T00:00:00Z", "tick": 5},
            edge_weight=1.5,
            edge_reason="source disagreement",
        )
        self.assertEqual(linked["event"]["event_type"], "linked")
        self.assertEqual(reinforced["event"]["event_type"], "reinforced")
        self.assertEqual(conflicted["event"]["event_type"], "conflicted")
        record = conflicted["record"]
        self.assertEqual(record["related_memory_ids"], [target] if isinstance(record["related_memory_ids"], list) else (target,))
        self.assertEqual(record["conflicted_memory_ids"], [target] if isinstance(record["conflicted_memory_ids"], list) else (target,))
        self.assertEqual(record["reinforcement_score"], 2.0)
        self.assertEqual(record["conflict_score"], 1.5)

    def test_graph_query_expansion_returns_direct_match_then_related_neighbor(self) -> None:
        runtime = open_runtime(keyring={"dev-key": b"super-secret"})
        source = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
        target = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
        runtime.ingest_event(
            _signed_event(
                sequence=1,
                event_id="11111111-1111-4111-8111-111111111111",
                event_type="created",
                previous_events=[],
                payload={"topic": "alpha signal"},
                memory_id=source,
            ),
            expected_tenant_id="tenant-alpha",
            trusted_context={"tenant_id": "tenant-alpha"},
        )
        runtime.ingest_event(
            _signed_event(
                sequence=2,
                event_id="22222222-2222-4222-8222-222222222222",
                event_type="created",
                previous_events=[],
                payload={"topic": "neighbor bravo"},
                memory_id=target,
            ),
            expected_tenant_id="tenant-alpha",
            trusted_context={"tenant_id": "tenant-alpha"},
        )
        runtime.link(
            source,
            target,
            actor={"id": "svc-memory", "kind": "service"},
            policy_context={"tenant_id": "tenant-alpha"},
            trusted_context={"tenant_id": "tenant-alpha"},
            event_id="33333333-3333-4333-8333-333333333333",
            timestamp={"wall_time": "2026-03-22T00:00:00Z", "tick": 3},
        )
        query = runtime.query(
            policy_context={"tenant_id": "tenant-alpha"},
            trusted_context={"tenant_id": "tenant-alpha"},
            query_text="alpha",
            graph_expand=True,
        )
        self.assertEqual(query["count"], 2)
        self.assertEqual(query["records"][0]["memory_id"], source)
        self.assertEqual(query["records"][0]["retrieval_mode"], "lexical_graph_v1")
        self.assertEqual(query["records"][1]["memory_id"], target)
        self.assertEqual(query["records"][1]["retrieval_mode"], "graph_expand_v1")

    def test_graph_query_filter_and_conflict_penalty_are_applied(self) -> None:
        runtime = open_runtime(keyring={"dev-key": b"super-secret"})
        first = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
        second = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
        runtime.ingest_event(
            _signed_event(
                sequence=1,
                event_id="11111111-1111-4111-8111-111111111111",
                event_type="created",
                previous_events=[],
                payload={"topic": "alpha alpha"},
                memory_id=first,
            ),
            expected_tenant_id="tenant-alpha",
            trusted_context={"tenant_id": "tenant-alpha"},
        )
        runtime.ingest_event(
            _signed_event(
                sequence=2,
                event_id="22222222-2222-4222-8222-222222222222",
                event_type="created",
                previous_events=[],
                payload={"topic": "alpha alpha"},
                memory_id=second,
            ),
            expected_tenant_id="tenant-alpha",
            trusted_context={"tenant_id": "tenant-alpha"},
        )
        runtime.reinforce(
            first,
            actor={"id": "svc-memory", "kind": "service"},
            policy_context={"tenant_id": "tenant-alpha"},
            trusted_context={"tenant_id": "tenant-alpha"},
            event_id="33333333-3333-4333-8333-333333333333",
            timestamp={"wall_time": "2026-03-22T00:00:00Z", "tick": 3},
            edge_weight=2.0,
        )
        runtime.conflict(
            second,
            first,
            actor={"id": "svc-memory", "kind": "service"},
            policy_context={"tenant_id": "tenant-alpha"},
            trusted_context={"tenant_id": "tenant-alpha"},
            event_id="44444444-4444-4444-8444-444444444444",
            timestamp={"wall_time": "2026-03-22T00:00:00Z", "tick": 4},
            edge_weight=2.0,
        )
        query = runtime.query(
            policy_context={"tenant_id": "tenant-alpha"},
            trusted_context={"tenant_id": "tenant-alpha"},
            query_text="alpha",
        )
        self.assertEqual(query["records"][0]["memory_id"], first)
        filtered = runtime.query(
            policy_context={"tenant_id": "tenant-alpha"},
            trusted_context={"tenant_id": "tenant-alpha"},
            query_text="alpha",
            structured_filter={"max_conflict_score": 0.0},
        )
        self.assertEqual(filtered["count"], 1)
        self.assertEqual(filtered["records"][0]["memory_id"], first)
