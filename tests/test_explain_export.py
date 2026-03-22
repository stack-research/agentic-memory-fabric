import pathlib
import sys
import unittest

PROJECT_ROOT = pathlib.Path(__file__).resolve().parents[1]
SRC_ROOT = PROJECT_ROOT / "src"
if str(SRC_ROOT) not in sys.path:
    sys.path.insert(0, str(SRC_ROOT))

from agentic_memory_fabric.events import EventEnvelope
from agentic_memory_fabric.explain import explain
from agentic_memory_fabric.export import export_provenance_log, export_sbom_snapshot
from agentic_memory_fabric.importer import import_records
from agentic_memory_fabric.policy import OVERRIDE_CAPABILITY, PolicyContext
from agentic_memory_fabric.replay import replay_events


def _event(
    sequence: int,
    event_id: str,
    memory_id: str,
    event_type: str,
    previous_events: list[str],
) -> EventEnvelope:
    payload_char = format(sequence % 16, "x")
    payload_hash = "sha256:" + (payload_char * 64)
    return EventEnvelope.from_dict(
        {
            "event_id": event_id,
            "sequence": sequence,
            "timestamp": {"wall_time": "2026-03-22T00:00:00Z", "tick": sequence},
            "actor": {"id": "svc-memory", "kind": "service"},
            "memory_id": memory_id,
            "event_type": event_type,
            "previous_events": previous_events,
            "payload_hash": payload_hash,
        }
    )


class ExplainExportTests(unittest.TestCase):
    def _events(self) -> list[EventEnvelope]:
        e1 = _event(
            1, "11111111-1111-4111-8111-111111111111", "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", "created", []
        )
        e2 = _event(
            2,
            "22222222-2222-4222-8222-222222222222",
            "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
            "updated",
            [e1.event_id],
        )
        e3 = _event(
            3, "33333333-3333-4333-8333-333333333333", "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb", "created", []
        )
        e4 = _event(
            4,
            "44444444-4444-4444-8444-444444444444",
            "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
            "quarantined",
            [e3.event_id],
        )
        e5 = _event(
            5, "55555555-5555-4555-8555-555555555555", "cccccccc-cccc-4ccc-8ccc-cccccccccccc", "created", []
        )
        e6 = _event(
            6,
            "66666666-6666-4666-8666-666666666666",
            "cccccccc-cccc-4ccc-8ccc-cccccccccccc",
            "expired",
            [e5.event_id],
        )
        e7 = _event(
            7, "77777777-7777-4777-8777-777777777777", "dddddddd-dddd-4ddd-8ddd-dddddddddddd", "created", []
        )
        e8 = _event(
            8,
            "88888888-8888-4888-8888-888888888888",
            "dddddddd-dddd-4ddd-8ddd-dddddddddddd",
            "deleted",
            [e7.event_id],
        )
        return [e1, e2, e3, e4, e5, e6, e7, e8]

    def test_explain_returns_ordered_memory_lineage(self) -> None:
        events = self._events()
        trace = explain("bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb", events)
        self.assertEqual([entry["sequence"] for entry in trace], [3, 4])
        self.assertEqual([entry["event_type"] for entry in trace], ["created", "quarantined"])
        self.assertEqual(trace[1]["previous_events"], ["33333333-3333-4333-8333-333333333333"])

    def test_snapshot_default_excludes_quarantined_expired_deleted(self) -> None:
        events = self._events()
        signature_states = {event.event_id: "verified" for event in events}
        state_map = replay_events(events, signature_states=signature_states)
        snapshot = export_sbom_snapshot(state_map, PolicyContext())
        self.assertEqual(snapshot["artifact_type"], "memory_sbom_snapshot")
        self.assertEqual(snapshot["count"], 1)
        self.assertEqual(
            [record["memory_id"] for record in snapshot["records"]],
            ["aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"],
        )

    def test_snapshot_override_includes_denied_states(self) -> None:
        events = self._events()
        signature_states = {event.event_id: "verified" for event in events}
        state_map = replay_events(events, signature_states=signature_states)
        snapshot = export_sbom_snapshot(
            state_map,
            PolicyContext(capabilities=frozenset({OVERRIDE_CAPABILITY})),
        )
        self.assertEqual(snapshot["count"], 4)
        memory_ids = {record["memory_id"] for record in snapshot["records"]}
        self.assertEqual(
            memory_ids,
            {
                "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
                "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
                "cccccccc-cccc-4ccc-8ccc-cccccccccccc",
                "dddddddd-dddd-4ddd-8ddd-dddddddddddd",
            },
        )

    def test_snapshot_default_denies_unsigned_signature_state(self) -> None:
        events = self._events()
        state_map = replay_events(events)
        snapshot = export_sbom_snapshot(state_map, PolicyContext())
        self.assertEqual(snapshot["count"], 0)

    def test_provenance_slice_contains_imported_events(self) -> None:
        imported_events = import_records(
            [
                {
                    "memory_id": "12121212-1212-4212-8212-121212121212",
                    "payload": {"k": "v"},
                    "source_id": "legacy-seed",
                }
            ],
            actor={"id": "migration-bot", "kind": "service"},
            start_sequence=1,
            default_timestamp="2026-03-22T00:00:00Z",
        )
        prov = export_provenance_log(imported_events)
        self.assertEqual(prov["count"], 1)
        self.assertEqual(prov["events"][0]["event_type"], "imported")

    def test_provenance_log_includes_full_history_and_range_filter(self) -> None:
        events = self._events()
        full_slice = export_provenance_log(events)
        self.assertEqual(full_slice["artifact_type"], "provenance_log_slice")
        self.assertEqual(full_slice["count"], 8)
        event_types = {entry["event_type"] for entry in full_slice["events"]}
        self.assertTrue({"quarantined", "expired", "deleted"}.issubset(event_types))

        range_slice = export_provenance_log(events, sequence_range=(3, 5))
        self.assertEqual([entry["sequence"] for entry in range_slice["events"]], [3, 4, 5])
        self.assertEqual(range_slice["sequence_range"], {"start": 3, "end": 5})
