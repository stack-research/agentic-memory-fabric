import pathlib
import sys
import unittest

PROJECT_ROOT = pathlib.Path(__file__).resolve().parents[1]
SRC_ROOT = PROJECT_ROOT / "src"
if str(SRC_ROOT) not in sys.path:
    sys.path.insert(0, str(SRC_ROOT))

from agentic_memory_fabric.export import export_provenance_log, export_sbom_snapshot
from agentic_memory_fabric.importer import append_imported_records, import_records
from agentic_memory_fabric.log import AppendOnlyEventLog
from agentic_memory_fabric.policy import OVERRIDE_CAPABILITY, PolicyContext
from agentic_memory_fabric.replay import replay_events


class ImporterTests(unittest.TestCase):
    def _records(self) -> list[dict]:
        return [
            {
                "memory_id": "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
                "payload": {"name": "alpha"},
                "source_id": "legacy-1",
            },
            {
                "memory_id": "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
                "payload": {"name": "alpha-v2"},
                "source_id": "legacy-2",
            },
            {
                "memory_id": "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
                "payload": {"name": "bravo"},
                "source_id": "legacy-3",
            },
        ]

    def test_import_creates_only_imported_events(self) -> None:
        events = import_records(
            self._records(),
            actor={"id": "migration-bot", "kind": "service"},
            start_sequence=1,
            default_timestamp="2026-03-22T00:00:00Z",
        )
        self.assertTrue(events)
        self.assertTrue(all(event.event_type == "imported" for event in events))

    def test_import_sequence_and_event_ids_are_deterministic(self) -> None:
        kwargs = {
            "records": self._records(),
            "actor": {"id": "migration-bot", "kind": "service"},
            "start_sequence": 10,
            "default_timestamp": "2026-03-22T00:00:00Z",
        }
        events_a = import_records(**kwargs)
        events_b = import_records(**kwargs)
        self.assertEqual([event.sequence for event in events_a], [10, 11, 12])
        self.assertEqual(
            [event.event_id for event in events_a],
            [event.event_id for event in events_b],
        )

    def test_replay_from_zero_consistency_for_imported_events(self) -> None:
        events = import_records(
            self._records(),
            actor={"id": "migration-bot", "kind": "service"},
            start_sequence=1,
            default_timestamp="2026-03-22T00:00:00Z",
        )
        first = replay_events(events)
        second = replay_events(events)
        self.assertEqual(first, second)

    def test_provenance_and_snapshot_reflect_imported_data(self) -> None:
        events = import_records(
            self._records(),
            actor={"id": "migration-bot", "kind": "service"},
            start_sequence=1,
            default_timestamp="2026-03-22T00:00:00Z",
        )
        prov = export_provenance_log(events)
        self.assertEqual(prov["count"], 3)
        self.assertTrue(all(entry["event_type"] == "imported" for entry in prov["events"]))

        state_map = replay_events(events)
        default_snapshot = export_sbom_snapshot(state_map, PolicyContext())
        self.assertEqual(default_snapshot["count"], 0)
        override_snapshot = export_sbom_snapshot(
            state_map,
            PolicyContext(capabilities=frozenset({OVERRIDE_CAPABILITY})),
        )
        self.assertEqual(override_snapshot["count"], 2)

    def test_import_requires_append_log_for_state_mutation(self) -> None:
        log = AppendOnlyEventLog()
        events = import_records(
            self._records(),
            actor={"id": "migration-bot", "kind": "service"},
            start_sequence=1,
            default_timestamp="2026-03-22T00:00:00Z",
        )
        self.assertEqual(len(log), 0)
        self.assertEqual(len(events), 3)

        appended = append_imported_records(
            log,
            self._records(),
            actor={"id": "migration-bot", "kind": "service"},
            start_sequence=1,
            default_timestamp="2026-03-22T00:00:00Z",
        )
        self.assertEqual(len(log), 3)
        self.assertEqual(len(appended), 3)
