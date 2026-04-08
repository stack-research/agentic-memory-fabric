import pathlib
import sys
import tempfile
import unittest

PROJECT_ROOT = pathlib.Path(__file__).resolve().parents[1]
SRC_ROOT = PROJECT_ROOT / "src"
if str(SRC_ROOT) not in sys.path:
    sys.path.insert(0, str(SRC_ROOT))

from agentic_memory_fabric.events import EventEnvelope, canonical_payload_hash
from agentic_memory_fabric.log import AppendOnlyEventLog
from agentic_memory_fabric.replay import LIFECYCLE_DELETED, replay_events
from agentic_memory_fabric.sqlite_store import SQLiteEventLog


def _event(
    sequence: int,
    event_id: str,
    event_type: str,
    previous_events: list[str],
    evidence_refs: list[dict] | None = None,
    attestation: dict | None = None,
    payload: object | None = None,
    memory_id: str = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
    memory_class: str | None = None,
    promoted_from_memory_ids: list[str] | None = None,
    promoted_from_event_ids: list[str] | None = None,
    resolved_from_memory_ids: list[str] | None = None,
    resolved_from_event_ids: list[str] | None = None,
    resolver_kind: str | None = None,
    resolution_reason: str | None = None,
    target_memory_id: str | None = None,
    edge_weight: float | None = None,
    edge_reason: str | None = None,
) -> EventEnvelope:
    if payload is None:
        payload_char = format(sequence % 16, "x")
        payload_hash = "sha256:" + (payload_char * 64)
    else:
        payload_hash = canonical_payload_hash(payload)
    event_data = {
        "event_id": event_id,
        "sequence": sequence,
        "timestamp": {"wall_time": "2026-03-22T00:00:00Z", "tick": sequence},
        "actor": {"id": "svc-memory", "kind": "service"},
        "tenant_id": "tenant-alpha",
        "memory_id": memory_id,
        "event_type": event_type,
        "previous_events": previous_events,
        "payload_hash": payload_hash,
    }
    if payload is not None:
        event_data["payload"] = payload
    if memory_class is not None:
        event_data["memory_class"] = memory_class
    if promoted_from_memory_ids is not None:
        event_data["promoted_from_memory_ids"] = promoted_from_memory_ids
    if promoted_from_event_ids is not None:
        event_data["promoted_from_event_ids"] = promoted_from_event_ids
    if resolved_from_memory_ids is not None:
        event_data["resolved_from_memory_ids"] = resolved_from_memory_ids
    if resolved_from_event_ids is not None:
        event_data["resolved_from_event_ids"] = resolved_from_event_ids
    if resolver_kind is not None:
        event_data["resolver_kind"] = resolver_kind
    if resolution_reason is not None:
        event_data["resolution_reason"] = resolution_reason
    if target_memory_id is not None:
        event_data["target_memory_id"] = target_memory_id
    if edge_weight is not None:
        event_data["edge_weight"] = edge_weight
    if edge_reason is not None:
        event_data["edge_reason"] = edge_reason
    if evidence_refs is not None:
        event_data["evidence_refs"] = evidence_refs
    if attestation is not None:
        event_data["attestation"] = attestation
    return EventEnvelope.from_dict(event_data)


class LogReplayTests(unittest.TestCase):
    def test_append_only_enforces_contiguous_sequence(self) -> None:
        log = AppendOnlyEventLog()
        first = _event(1, "11111111-1111-4111-8111-111111111111", "created", [])
        log.append(first)

        third = _event(
            3,
            "33333333-3333-4333-8333-333333333333",
            "updated",
            ["11111111-1111-4111-8111-111111111111"],
        )
        with self.assertRaisesRegex(ValueError, "contiguous"):
            log.append(third)

    def test_append_only_rejects_duplicate_event_id(self) -> None:
        log = AppendOnlyEventLog()
        first = _event(1, "11111111-1111-4111-8111-111111111111", "created", [])
        second = _event(
            2,
            "11111111-1111-4111-8111-111111111111",
            "updated",
            ["11111111-1111-4111-8111-111111111111"],
        )
        log.append(first)
        with self.assertRaisesRegex(ValueError, "duplicate event_id"):
            log.append(second)

    def test_replay_is_deterministic_and_preserves_lineage(self) -> None:
        log = AppendOnlyEventLog()
        e1 = _event(1, "11111111-1111-4111-8111-111111111111", "created", [])
        e2 = _event(2, "22222222-2222-4222-8222-222222222222", "updated", [e1.event_id])
        e3 = _event(3, "33333333-3333-4333-8333-333333333333", "quarantined", [e2.event_id])
        e4 = _event(4, "44444444-4444-4444-8444-444444444444", "expired", [e3.event_id])
        e5 = _event(5, "55555555-5555-4555-8555-555555555555", "deleted", [e4.event_id])
        for event in (e1, e2, e3, e4, e5):
            log.append(event)

        state_once = replay_events(log.all_events())
        state_twice = replay_events(log.all_events())
        self.assertEqual(state_once, state_twice)

        state = state_once["aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"]
        self.assertEqual(state.version, 2)
        self.assertEqual(state.last_event_type, "deleted")
        self.assertEqual(state.last_event_id, e5.event_id)
        self.assertEqual(state.lifecycle_state, LIFECYCLE_DELETED)
        self.assertEqual(state.previous_events, (e4.event_id,))
        self.assertEqual(state.lineage_depth, 5)

    def test_state_transition_across_core_event_types(self) -> None:
        e1 = _event(1, "11111111-1111-4111-8111-111111111111", "created", [])
        e2 = _event(2, "22222222-2222-4222-8222-222222222222", "updated", [e1.event_id])
        e3 = _event(3, "33333333-3333-4333-8333-333333333333", "quarantined", [e2.event_id])
        e4 = _event(4, "44444444-4444-4444-8444-444444444444", "expired", [e3.event_id])
        e5 = _event(5, "55555555-5555-4555-8555-555555555555", "deleted", [e4.event_id])

        s1 = replay_events([e1])["aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"]
        s2 = replay_events([e1, e2])["aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"]
        s3 = replay_events([e1, e2, e3])["aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"]
        s4 = replay_events([e1, e2, e3, e4])["aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"]
        s5 = replay_events([e1, e2, e3, e4, e5])["aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"]

        self.assertEqual(s1.trust_state, "trusted")
        self.assertEqual(s2.trust_state, "trusted")
        self.assertEqual(s3.trust_state, "quarantined")
        self.assertEqual(s4.trust_state, "expired")
        self.assertEqual(s5.trust_state, "expired")
        self.assertEqual(s5.lifecycle_state, LIFECYCLE_DELETED)

    def test_imported_event_is_treated_as_trusted_in_replay(self) -> None:
        imported = _event(
            1,
            "99999999-9999-4999-8999-999999999999",
            "imported",
            [],
            evidence_refs=[{"type": "opaque", "ref": "import:seed-1"}],
        )
        state = replay_events([imported])["aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"]
        self.assertEqual(state.trust_state, "trusted")
        self.assertEqual(state.last_event_type, "imported")
        self.assertEqual(state.version, 1)
        self.assertEqual(state.memory_class, "episodic")

    def test_sqlite_log_persists_events_and_signature_state_across_restart(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = pathlib.Path(tmpdir) / "events.db"
            first = _event(1, "11111111-1111-4111-8111-111111111111", "created", [])
            second = _event(
                2,
                "22222222-2222-4222-8222-222222222222",
                "updated",
                ["11111111-1111-4111-8111-111111111111"],
            )

            log = SQLiteEventLog(db_path)
            try:
                log.append(first, signature_verifier=lambda _: "verified")
                log.append(second, signature_verifier=lambda _: "invalid")
            finally:
                log.close()

            reopened = SQLiteEventLog(db_path)
            try:
                self.assertEqual(len(reopened), 2)
                events = reopened.all_events()
                self.assertEqual(events[0].event_id, first.event_id)
                self.assertEqual(events[1].event_id, second.event_id)
                self.assertEqual(reopened.signature_state_for_event(first.event_id), "verified")
                self.assertEqual(reopened.signature_state_for_event(second.event_id), "invalid")
                state = replay_events(events, signature_states=reopened.signature_states())
                self.assertEqual(
                    state["aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"].signature_state,
                    "invalid",
                )
                self.assertEqual(
                    reopened.signature_states(),
                    {
                        "11111111-1111-4111-8111-111111111111": "verified",
                        "22222222-2222-4222-8222-222222222222": "invalid",
                    },
                )
            finally:
                reopened.close()

    def test_sqlite_log_persists_lifecycle_signature_states(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = pathlib.Path(tmpdir) / "events.db"
            first = _event(1, "11111111-1111-4111-8111-111111111111", "created", [])
            second = _event(
                2,
                "22222222-2222-4222-8222-222222222222",
                "updated",
                [first.event_id],
            )
            log = SQLiteEventLog(db_path)
            try:
                log.append(first, signature_verifier=lambda _: "key_missing")
                log.append(second, signature_verifier=lambda _: "revoked")
            finally:
                log.close()

            reopened = SQLiteEventLog(db_path)
            try:
                states = reopened.signature_states()
                self.assertEqual(states[first.event_id], "key_missing")
                self.assertEqual(states[second.event_id], "revoked")
            finally:
                reopened.close()

    def test_sqlite_single_pass_read_returns_events_and_signature_states(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = pathlib.Path(tmpdir) / "events.db"
            first = _event(1, "11111111-1111-4111-8111-111111111111", "created", [])
            second = _event(
                2,
                "22222222-2222-4222-8222-222222222222",
                "updated",
                [first.event_id],
            )
            log = SQLiteEventLog(db_path)
            try:
                log.append(first, signature_verifier=lambda _: "verified")
                log.append(second, signature_verifier=lambda _: "invalid")
                events, states = log.all_events_with_signature_states()
                self.assertEqual([event.event_id for event in events], [first.event_id, second.event_id])
                self.assertEqual(
                    states,
                    {
                        first.event_id: "verified",
                        second.event_id: "invalid",
                    },
                )
            finally:
                log.close()

    def test_sqlite_events_in_sequence_range_filters_rows(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = pathlib.Path(tmpdir) / "events.db"
            first = _event(1, "11111111-1111-4111-8111-111111111111", "created", [])
            second = _event(
                2,
                "22222222-2222-4222-8222-222222222222",
                "updated",
                [first.event_id],
            )
            third = _event(
                3,
                "33333333-3333-4333-8333-333333333333",
                "expired",
                [second.event_id],
            )
            log = SQLiteEventLog(db_path)
            try:
                log.append(first)
                log.append(second)
                log.append(third)
                subset = log.events_in_sequence_range(start=2, end=3)
                self.assertEqual([event.event_id for event in subset], [second.event_id, third.event_id])
            finally:
                log.close()

    def test_graph_events_materialize_graph_state(self) -> None:
        source = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
        target = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
        source_created = _event(
            1,
            "11111111-1111-4111-8111-111111111111",
            "created",
            [],
            payload={"topic": "alpha"},
            memory_id=source,
        )
        target_created = _event(
            2,
            "22222222-2222-4222-8222-222222222222",
            "created",
            [],
            payload={"topic": "beta"},
            memory_id=target,
        )
        linked = _event(
            3,
            "33333333-3333-4333-8333-333333333333",
            "linked",
            [source_created.event_id],
            memory_id=source,
            target_memory_id=target,
            payload={"topic": "alpha"},
        )
        reinforced = _event(
            4,
            "44444444-4444-4444-8444-444444444444",
            "reinforced",
            [linked.event_id],
            memory_id=source,
            target_memory_id=target,
            edge_weight=2.0,
            payload={"topic": "alpha"},
        )
        conflicted = _event(
            5,
            "55555555-5555-4555-8555-555555555555",
            "conflicted",
            [reinforced.event_id],
            memory_id=source,
            target_memory_id=target,
            edge_weight=1.5,
            payload={"topic": "alpha"},
        )
        state = replay_events([source_created, target_created, linked, reinforced, conflicted])[source]
        self.assertEqual(state.related_memory_ids, (target,))
        self.assertEqual(state.conflicted_memory_ids, (target,))
        self.assertEqual(state.relationship_edges, ((target, "linked"), (target, "reinforced"), (target, "conflicted")))
        self.assertEqual(state.reinforcement_score, 2.0)
        self.assertEqual(state.conflict_score, 1.5)

    def test_merge_resolution_events_materialize_resolution_state(self) -> None:
        left = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
        right = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
        merged = "cccccccc-cccc-4ccc-8ccc-cccccccccccc"
        left_created = _event(
            1,
            "11111111-1111-4111-8111-111111111111",
            "created",
            [],
            payload={"topic": "alpha"},
            memory_id=left,
        )
        right_created = _event(
            2,
            "22222222-2222-4222-8222-222222222222",
            "created",
            [],
            payload={"topic": "bravo"},
            memory_id=right,
        )
        conflict = _event(
            3,
            "33333333-3333-4333-8333-333333333333",
            "conflicted",
            [left_created.event_id],
            payload={"topic": "alpha"},
            memory_id=left,
            target_memory_id=right,
        )
        proposal = _event(
            4,
            "44444444-4444-4444-8444-444444444444",
            "merge_proposed",
            [conflict.event_id, right_created.event_id],
            payload={"topic": "merged"},
            memory_id=merged,
            memory_class="semantic",
            resolved_from_memory_ids=[left, right],
            resolved_from_event_ids=[conflict.event_id, right_created.event_id],
            resolver_kind="human_gate",
        )
        # Build the approval event manually to preserve payload_hash without payload replacement.
        approved = EventEnvelope.from_dict(
            {
                "event_id": "55555555-5555-4555-8555-555555555555",
                "sequence": 5,
                "timestamp": {"wall_time": "2026-03-22T00:00:00Z", "tick": 5},
                "actor": {"id": "svc-memory", "kind": "service"},
                "tenant_id": "tenant-alpha",
                "memory_id": merged,
                "event_type": "merge_approved",
                "previous_events": [proposal.event_id],
                "payload_hash": canonical_payload_hash({"topic": "merged"}),
                "resolution_reason": "reviewed",
            }
        )
        state_map = replay_events([left_created, right_created, conflict, proposal, approved])
        merged_state = state_map[merged]
        self.assertFalse(merged_state.conflict_open)
        self.assertEqual(merged_state.resolved_from_memory_ids, (left, right))
        self.assertEqual(merged_state.memory_class, "semantic")
        self.assertEqual(state_map[left].merged_into_memory_id, merged)
        self.assertEqual(state_map[left].superseded_by_memory_id, merged)

    def test_replay_materializes_attestation_fields(self) -> None:
        attested = _event(
            1,
            "99999999-9999-4999-8999-999999999999",
            "attested",
            [],
            attestation={
                "issuer": "issuer-alpha",
                "issued_at": "2026-03-22T00:00:00Z",
                "trust_level": "high",
                "claims": {"ticket": "T-123"},
            },
        )
        state = replay_events([attested])["aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"]
        self.assertTrue(state.has_attestation)
        self.assertEqual(state.attestation_issuer, "issuer-alpha")
        self.assertEqual(state.attestation_trust_level, "high")

    def test_replay_tracks_recall_and_reconsolidation_dynamics(self) -> None:
        created = _event(
            1,
            "11111111-1111-4111-8111-111111111111",
            "created",
            [],
            payload={"topic": "alpha"},
        )
        recalled = EventEnvelope.from_dict(
            {
                "event_id": "22222222-2222-4222-8222-222222222222",
                "sequence": 2,
                "timestamp": {"wall_time": "2026-03-22T00:00:00Z", "tick": 20},
                "actor": {"id": "svc-memory", "kind": "service"},
                "tenant_id": "tenant-alpha",
                "memory_id": "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
                "event_type": "recalled",
                "previous_events": [created.event_id],
                "payload_hash": created.payload_hash,
            }
        )
        reconsolidated = EventEnvelope.from_dict(
            {
                "event_id": "33333333-3333-4333-8333-333333333333",
                "sequence": 3,
                "timestamp": {"wall_time": "2026-03-22T00:00:00Z", "tick": 30},
                "actor": {"id": "svc-memory", "kind": "service"},
                "tenant_id": "tenant-alpha",
                "memory_id": "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
                "event_type": "reconsolidated",
                "previous_events": [recalled.event_id],
                "payload": {"topic": "beta"},
                "payload_hash": canonical_payload_hash({"topic": "beta"}),
            }
        )
        state = replay_events([created, recalled, reconsolidated])[
            "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
        ]
        self.assertEqual(state.version, 2)
        self.assertEqual(state.lineage_depth, 3)
        self.assertEqual(state.recall_count, 1)
        self.assertEqual(state.reconsolidation_count, 1)
        self.assertEqual(state.last_access_tick, 30)
        self.assertEqual(state.last_recall_tick, 30)
        self.assertEqual(state.last_write_tick, 30)
        self.assertEqual(state.payload, {"topic": "beta"})
        self.assertEqual(state.retrieval_text, '{"topic":"beta"}')
        self.assertTrue(state.queryable_payload_present)

    def test_replay_materializes_promoted_semantic_memory(self) -> None:
        source = _event(
            1,
            "11111111-1111-4111-8111-111111111111",
            "created",
            [],
            payload={"topic": "episodic-alpha"},
        )
        promoted = _event(
            2,
            "22222222-2222-4222-8222-222222222222",
            "promoted",
            [source.event_id],
            memory_id="bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
            memory_class="semantic",
            payload={"topic": "semantic-alpha"},
            promoted_from_memory_ids=[source.memory_id],
            promoted_from_event_ids=[source.event_id],
        )
        state_map = replay_events([source, promoted])
        promoted_state = state_map["bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"]
        self.assertEqual(promoted_state.memory_class, "semantic")
        self.assertEqual(promoted_state.promoted_from_memory_ids, (source.memory_id,))
        self.assertFalse(promoted_state.promotion_eligible)
        self.assertEqual(promoted_state.version, 1)

    def test_sqlite_log_enforces_invariants_after_reopen(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = pathlib.Path(tmpdir) / "events.db"
            first = _event(1, "11111111-1111-4111-8111-111111111111", "created", [])

            log = SQLiteEventLog(db_path)
            try:
                log.append(first)
            finally:
                log.close()

            reopened = SQLiteEventLog(db_path)
            try:
                duplicate = _event(
                    2,
                    "11111111-1111-4111-8111-111111111111",
                    "updated",
                    [first.event_id],
                )
                with self.assertRaisesRegex(ValueError, "duplicate event_id"):
                    reopened.append(duplicate)

                non_contiguous = _event(
                    3,
                    "33333333-3333-4333-8333-333333333333",
                    "updated",
                    [first.event_id],
                )
                with self.assertRaisesRegex(ValueError, "contiguous"):
                    reopened.append(non_contiguous)
            finally:
                reopened.close()
