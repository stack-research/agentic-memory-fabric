import pathlib
import sys
import unittest

PROJECT_ROOT = pathlib.Path(__file__).resolve().parents[1]
SRC_ROOT = PROJECT_ROOT / "src"
if str(SRC_ROOT) not in sys.path:
    sys.path.insert(0, str(SRC_ROOT))

from agentic_memory_fabric.export import export_provenance_log, export_sbom_snapshot
from agentic_memory_fabric.crypto import sign_event, verify_event_signature
from agentic_memory_fabric.importer import append_imported_records, import_records
from agentic_memory_fabric.log import AppendOnlyEventLog
from agentic_memory_fabric.policy import OVERRIDE_CAPABILITY, PolicyContext
from agentic_memory_fabric.replay import replay_events


class ImporterTests(unittest.TestCase):
    def _records(self) -> list[dict]:
        return [
            {
                "tenant_id": "tenant-alpha",
                "memory_id": "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
                "payload": {"name": "alpha"},
                "source_id": "legacy-1",
            },
            {
                "tenant_id": "tenant-alpha",
                "memory_id": "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
                "payload": {"name": "alpha-v2"},
                "source_id": "legacy-2",
            },
            {
                "tenant_id": "tenant-alpha",
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

    def test_import_preserves_inline_payload_for_semantic_query_materialization(self) -> None:
        events = import_records(
            self._records(),
            actor={"id": "migration-bot", "kind": "service"},
            start_sequence=1,
            default_timestamp="2026-03-22T00:00:00Z",
        )
        state = replay_events(events)["aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"]
        self.assertEqual(state.payload, {"name": "alpha-v2"})
        self.assertEqual(state.retrieval_text, '{"name":"alpha-v2"}')
        self.assertTrue(state.queryable_payload_present)

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
        default_snapshot = export_sbom_snapshot(state_map, PolicyContext(tenant_id="tenant-alpha"))
        self.assertEqual(default_snapshot["count"], 0)
        override_snapshot = export_sbom_snapshot(
            state_map,
            PolicyContext(
                capabilities=frozenset({OVERRIDE_CAPABILITY}),
                tenant_id="tenant-alpha",
                trusted_subject=True,
            ),
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

    def test_import_path_uses_same_signature_verifier_when_provided(self) -> None:
        seed_record = {
            "event_id": "11111111-1111-4111-8111-111111111111",
            "memory_id": "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
            "tenant_id": "tenant-alpha",
            "payload_hash": "sha256:" + ("a" * 64),
            "previous_events": [],
            "source_id": "seed-1",
            "timestamp": {"wall_time": "2026-03-22T00:00:00Z", "tick": 1},
            "evidence_refs": [{"type": "opaque", "ref": "import:seed-1"}],
        }
        unsigned = import_records(
            [seed_record],
            actor={"id": "migration-bot", "kind": "service"},
            start_sequence=1,
            default_timestamp="2026-03-22T00:00:00Z",
            tenant_id="tenant-alpha",
        )[0]
        sig = sign_event(unsigned, key_id="dev-key", key=b"super-secret")
        record = {
            "event_id": unsigned.event_id,
            "memory_id": unsigned.memory_id,
            "tenant_id": unsigned.tenant_id,
            "payload_hash": unsigned.payload_hash,
            "previous_events": [],
            "source_id": "seed-1",
            "timestamp": unsigned.timestamp.to_dict(),
            "evidence_refs": [{"type": "opaque", "ref": "import:seed-1"}],
            "signature": {"alg": "hmac-sha256", "key_id": "dev-key", "sig": sig},
        }
        log = AppendOnlyEventLog()
        append_imported_records(
            log,
            [record],
            actor={"id": "migration-bot", "kind": "service"},
            start_sequence=1,
            default_timestamp="2026-03-22T00:00:00Z",
            tenant_id="tenant-alpha",
            signature_verifier=lambda event: verify_event_signature(
                event,
                key_resolver=lambda key_id: {"dev-key": b"super-secret"}.get(key_id),
            ),
        )
        self.assertEqual(log.signature_state_for_event(unsigned.event_id), "verified")
