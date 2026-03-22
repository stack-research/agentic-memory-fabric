import pathlib
import sys
import tempfile
import unittest

PROJECT_ROOT = pathlib.Path(__file__).resolve().parents[1]
SRC_ROOT = PROJECT_ROOT / "src"
if str(SRC_ROOT) not in sys.path:
    sys.path.insert(0, str(SRC_ROOT))

from agentic_memory_fabric.events import EventEnvelope
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
) -> EventEnvelope:
    payload_char = format(sequence % 16, "x")
    payload_hash = "sha256:" + (payload_char * 64)
    event_data = {
        "event_id": event_id,
        "sequence": sequence,
        "timestamp": {"wall_time": "2026-03-22T00:00:00Z", "tick": sequence},
        "actor": {"id": "svc-memory", "kind": "service"},
        "tenant_id": "tenant-alpha",
        "memory_id": "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
        "event_type": event_type,
        "previous_events": previous_events,
        "payload_hash": payload_hash,
    }
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
        self.assertEqual(state.version, 5)
        self.assertEqual(state.last_event_type, "deleted")
        self.assertEqual(state.last_event_id, e5.event_id)
        self.assertEqual(state.lifecycle_state, LIFECYCLE_DELETED)
        self.assertEqual(state.previous_events, (e4.event_id,))

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
