import pathlib
import sys
import unittest

PROJECT_ROOT = pathlib.Path(__file__).resolve().parents[1]
SRC_ROOT = PROJECT_ROOT / "src"
if str(SRC_ROOT) not in sys.path:
    sys.path.insert(0, str(SRC_ROOT))

from agentic_memory_fabric.events import EventEnvelope, canonical_payload_hash
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
    payload: object | None = None,
    memory_class: str | None = None,
    promoted_from_memory_ids: list[str] | None = None,
    promoted_from_event_ids: list[str] | None = None,
    target_memory_id: str | None = None,
    edge_weight: float | None = None,
    edge_reason: str | None = None,
) -> EventEnvelope:
    if payload is None:
        payload_char = format(sequence % 16, "x")
        payload_hash = "sha256:" + (payload_char * 64)
    else:
        payload_hash = canonical_payload_hash(payload)
    return EventEnvelope.from_dict(
        {
            "event_id": event_id,
            "sequence": sequence,
            "timestamp": {"wall_time": "2026-03-22T00:00:00Z", "tick": sequence},
            "actor": {"id": "svc-memory", "kind": "service"},
            "tenant_id": "tenant-alpha",
            "memory_id": memory_id,
            "event_type": event_type,
            "previous_events": previous_events,
            "payload_hash": payload_hash,
            **({"payload": payload} if payload is not None else {}),
            **({"memory_class": memory_class} if memory_class is not None else {}),
            **(
                {"promoted_from_memory_ids": promoted_from_memory_ids}
                if promoted_from_memory_ids is not None
                else {}
            ),
            **(
                {"promoted_from_event_ids": promoted_from_event_ids}
                if promoted_from_event_ids is not None
                else {}
            ),
            **({"target_memory_id": target_memory_id} if target_memory_id is not None else {}),
            **({"edge_weight": edge_weight} if edge_weight is not None else {}),
            **({"edge_reason": edge_reason} if edge_reason is not None else {}),
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
        snapshot = export_sbom_snapshot(state_map, PolicyContext(tenant_id="tenant-alpha"))
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
            PolicyContext(
                capabilities=frozenset({OVERRIDE_CAPABILITY}),
                tenant_id="tenant-alpha",
                trusted_subject=True,
            ),
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
        snapshot = export_sbom_snapshot(state_map, PolicyContext(tenant_id="tenant-alpha"))
        self.assertEqual(snapshot["count"], 0)

    def test_provenance_slice_contains_imported_events(self) -> None:
        imported_events = import_records(
            [
                {
                    "memory_id": "12121212-1212-4212-8212-121212121212",
                    "tenant_id": "tenant-alpha",
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

    def test_explain_and_snapshot_include_promotion_lineage_fields(self) -> None:
        source = _event(
            1,
            "11111111-1111-4111-8111-111111111111",
            "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
            "created",
            [],
            payload={"topic": "episodic alpha"},
        )
        promoted = _event(
            2,
            "22222222-2222-4222-8222-222222222222",
            "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
            "promoted",
            [source.event_id],
            payload={"topic": "semantic alpha"},
            memory_class="semantic",
            promoted_from_memory_ids=[source.memory_id],
            promoted_from_event_ids=[source.event_id],
        )
        trace = explain("bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb", [source, promoted])
        self.assertEqual(trace[0]["event_type"], "promoted")
        self.assertEqual(
            trace[0]["promoted_from_memory_ids"],
            ["aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"],
        )

        state_map = replay_events(
            [source, promoted],
            signature_states={
                source.event_id: "verified",
                promoted.event_id: "verified",
            },
        )
        snapshot = export_sbom_snapshot(state_map, PolicyContext(tenant_id="tenant-alpha"))
        self.assertEqual(snapshot["records"][0]["memory_class"], "semantic")
        self.assertEqual(
            snapshot["records"][0]["promoted_from_memory_ids"],
            ["aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"],
        )

    def test_explain_and_snapshot_include_graph_fields(self) -> None:
        source = _event(
            1,
            "11111111-1111-4111-8111-111111111111",
            "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
            "created",
            [],
            payload={"topic": "alpha"},
        )
        target = _event(
            2,
            "22222222-2222-4222-8222-222222222222",
            "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
            "created",
            [],
            payload={"topic": "beta"},
        )
        linked = _event(
            3,
            "33333333-3333-4333-8333-333333333333",
            "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
            "linked",
            [source.event_id],
            target_memory_id=target.memory_id,
            edge_reason="related",
        )
        reinforced = _event(
            4,
            "44444444-4444-4444-8444-444444444444",
            "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
            "reinforced",
            [linked.event_id],
            target_memory_id=target.memory_id,
            edge_weight=2.0,
        )
        trace = explain(source.memory_id, [source, target, linked, reinforced])
        self.assertEqual(trace[1]["target_memory_id"], target.memory_id)
        self.assertEqual(trace[1]["edge_reason"], "related")
        self.assertEqual(trace[2]["edge_weight"], 2.0)

        state_map = replay_events(
            [source, target, linked, reinforced],
            signature_states={
                source.event_id: "verified",
                target.event_id: "verified",
                linked.event_id: "verified",
                reinforced.event_id: "verified",
            },
        )
        snapshot = export_sbom_snapshot(state_map, PolicyContext(tenant_id="tenant-alpha"))
        source_record = next(
            record for record in snapshot["records"] if record["memory_id"] == source.memory_id
        )
        self.assertEqual(source_record["related_memory_ids"], [target.memory_id])
        self.assertEqual(source_record["reinforcement_score"], 2.0)
