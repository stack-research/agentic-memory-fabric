import pathlib
import sys
import unittest

PROJECT_ROOT = pathlib.Path(__file__).resolve().parents[1]
SRC_ROOT = PROJECT_ROOT / "src"
if str(SRC_ROOT) not in sys.path:
    sys.path.insert(0, str(SRC_ROOT))

from agentic_memory_fabric.events import EventEnvelope
from agentic_memory_fabric.log import AppendOnlyEventLog
from agentic_memory_fabric.replay import LIFECYCLE_DELETED, replay_events


def _event(sequence: int, event_id: str, event_type: str, previous_events: list[str]) -> EventEnvelope:
    payload_char = format(sequence % 16, "x")
    payload_hash = "sha256:" + (payload_char * 64)
    return EventEnvelope.from_dict(
        {
            "event_id": event_id,
            "sequence": sequence,
            "timestamp": {"wall_time": "2026-03-22T00:00:00Z", "tick": sequence},
            "actor": {"id": "svc-memory", "kind": "service"},
            "memory_id": "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
            "event_type": event_type,
            "previous_events": previous_events,
            "payload_hash": payload_hash,
        }
    )


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
