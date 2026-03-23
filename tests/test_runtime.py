import pathlib
import sys
import tempfile
import unittest

PROJECT_ROOT = pathlib.Path(__file__).resolve().parents[1]
SRC_ROOT = PROJECT_ROOT / "src"
if str(SRC_ROOT) not in sys.path:
    sys.path.insert(0, str(SRC_ROOT))

from agentic_memory_fabric.crypto import sign_event
from agentic_memory_fabric.events import EventEnvelope
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
) -> dict:
    payload_char = format(sequence % 16, "x")
    payload_hash = "sha256:" + (payload_char * 64)
    return {
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


def _signed_event(
    *,
    sequence: int,
    event_id: str,
    event_type: str,
    previous_events: list[str],
    key_id: str = "dev-key",
    key: bytes = b"super-secret",
) -> dict:
    event = EventEnvelope.from_dict(
        _event(
            sequence=sequence,
            event_id=event_id,
            event_type=event_type,
            previous_events=previous_events,
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
