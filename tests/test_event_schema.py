import json
import pathlib
import sys
import unittest

PROJECT_ROOT = pathlib.Path(__file__).resolve().parents[1]
SRC_ROOT = PROJECT_ROOT / "src"
if str(SRC_ROOT) not in sys.path:
    sys.path.insert(0, str(SRC_ROOT))

from agentic_memory_fabric.events import canonical_payload_hash, validate_event_envelope


def _valid_event() -> dict:
    return {
        "event_id": "11111111-1111-4111-8111-111111111111",
        "sequence": 1,
        "timestamp": {"wall_time": "2026-03-22T00:00:00Z", "tick": 0},
        "actor": {"id": "svc-memory", "kind": "service"},
        "tenant_id": "tenant-alpha",
        "memory_id": "22222222-2222-4222-8222-222222222222",
        "event_type": "created",
        "previous_events": [],
        "payload_hash": "sha256:" + ("a" * 64),
        "evidence_refs": [{"type": "tool_run_id", "ref": "run-123"}],
    }


class EventSchemaTests(unittest.TestCase):
    def test_event_schema_file_contains_required_structure(self) -> None:
        for schema_name in (
            "event-envelope.v0.json",
            "event-envelope.v1.json",
            "event-envelope.v2.json",
            "event-envelope.v3.json",
            "event-envelope.v4.json",
        ):
            schema_path = PROJECT_ROOT / "schemas" / schema_name
            schema = json.loads(schema_path.read_text(encoding="utf-8"))

            required = set(schema["required"])
            self.assertTrue(
                {
                    "event_id",
                    "sequence",
                    "timestamp",
                    "actor",
                    "tenant_id",
                    "memory_id",
                    "event_type",
                    "previous_events",
                    "payload_hash",
                }.issubset(required)
            )

            event_types = set(schema["properties"]["event_type"]["enum"])
            self.assertTrue(
                {"created", "updated", "quarantined", "expired", "deleted"}.issubset(
                    event_types
                )
            )
            if schema_name.endswith("v1.json"):
                self.assertIn("recalled", event_types)
                self.assertIn("reconsolidated", event_types)
            if schema_name.endswith("v2.json"):
                self.assertIn("payload", schema["properties"])
            if schema_name.endswith("v3.json"):
                self.assertIn("memory_class", schema["properties"])
                self.assertIn("promoted", event_types)
                self.assertIn("promoted_from_memory_ids", schema["properties"])
                self.assertIn("promoted_from_event_ids", schema["properties"])
            if schema_name.endswith("v4.json"):
                self.assertIn("linked", event_types)
                self.assertIn("reinforced", event_types)
                self.assertIn("conflicted", event_types)
                self.assertIn("target_memory_id", schema["properties"])
                self.assertIn("edge_weight", schema["properties"])
                self.assertIn("edge_reason", schema["properties"])
            self.assertIn("signature", schema["properties"])
            self.assertIn("attestation", schema["properties"])
            self.assertIn("ed25519", schema["properties"]["signature"]["properties"]["alg"]["enum"])

    def test_validate_event_envelope_accepts_valid_shape(self) -> None:
        validate_event_envelope(_valid_event())

    def test_validate_event_envelope_rejects_missing_required(self) -> None:
        event = _valid_event()
        event.pop("event_type")
        with self.assertRaisesRegex(ValueError, "Missing required fields"):
            validate_event_envelope(event)

    def test_validate_event_envelope_rejects_duplicate_lineage_edges(self) -> None:
        event = _valid_event()
        prev = "33333333-3333-4333-8333-333333333333"
        event["previous_events"] = [prev, prev]
        with self.assertRaisesRegex(ValueError, "must not contain duplicates"):
            validate_event_envelope(event)

    def test_validate_event_envelope_rejects_bad_payload_hash(self) -> None:
        event = _valid_event()
        event["payload_hash"] = "sha256:not-hex"
        with self.assertRaisesRegex(ValueError, "payload_hash"):
            validate_event_envelope(event)

    def test_validate_event_envelope_accepts_signature_and_attestation(self) -> None:
        event = _valid_event()
        event["signature"] = {
            "alg": "ed25519",
            "key_id": "dev-key",
            "sig": "YWJjZA==",
        }
        event["attestation"] = {
            "issuer": "security-service",
            "issued_at": "2026-03-22T00:00:00Z",
            "trust_level": "high",
            "claims": {"scope": "test"},
        }
        validate_event_envelope(event)

    def test_validate_event_envelope_accepts_inline_payload_when_hash_matches(self) -> None:
        event = _valid_event()
        event["payload"] = {"topic": "alpha", "steps": ["one", "two"]}
        event["payload_hash"] = canonical_payload_hash(event["payload"])
        validate_event_envelope(event)

    def test_validate_event_envelope_rejects_inline_payload_hash_mismatch(self) -> None:
        event = _valid_event()
        event["payload"] = {"topic": "alpha"}
        with self.assertRaisesRegex(ValueError, "canonical hash of payload"):
            validate_event_envelope(event)

    def test_validate_event_envelope_accepts_promoted_event_shape(self) -> None:
        payload = {"topic": "semantic-alpha"}
        event = {
            **_valid_event(),
            "memory_id": "55555555-5555-4555-8555-555555555555",
            "event_type": "promoted",
            "memory_class": "semantic",
            "payload": payload,
            "payload_hash": canonical_payload_hash(payload),
            "previous_events": ["33333333-3333-4333-8333-333333333333"],
            "promoted_from_memory_ids": ["22222222-2222-4222-8222-222222222222"],
            "promoted_from_event_ids": ["33333333-3333-4333-8333-333333333333"],
        }
        validate_event_envelope(event)

    def test_validate_event_envelope_rejects_promoted_event_without_semantic_class(self) -> None:
        payload = {"topic": "semantic-alpha"}
        event = {
            **_valid_event(),
            "memory_id": "55555555-5555-4555-8555-555555555555",
            "event_type": "promoted",
            "payload": payload,
            "payload_hash": canonical_payload_hash(payload),
            "previous_events": ["33333333-3333-4333-8333-333333333333"],
            "promoted_from_memory_ids": ["22222222-2222-4222-8222-222222222222"],
            "promoted_from_event_ids": ["33333333-3333-4333-8333-333333333333"],
        }
        with self.assertRaisesRegex(ValueError, "memory_class"):
            validate_event_envelope(event)

    def test_validate_event_envelope_rejects_invalid_signature_algorithm(self) -> None:
        event = _valid_event()
        event["signature"] = {
            "alg": "rsa-sha256",
            "key_id": "dev-key",
            "sig": "YWJjZA==",
        }
        with self.assertRaisesRegex(ValueError, "signature.alg"):
            validate_event_envelope(event)

    def test_validate_event_envelope_accepts_graph_edge_event(self) -> None:
        event = {
            **_valid_event(),
            "event_type": "linked",
            "previous_events": ["33333333-3333-4333-8333-333333333333"],
            "target_memory_id": "44444444-4444-4444-8444-444444444444",
            "edge_weight": 1.5,
            "edge_reason": "semantic-neighbor",
        }
        validate_event_envelope(event)

    def test_validate_event_envelope_rejects_link_without_target(self) -> None:
        event = {
            **_valid_event(),
            "event_type": "linked",
            "previous_events": ["33333333-3333-4333-8333-333333333333"],
        }
        with self.assertRaisesRegex(ValueError, "target_memory_id"):
            validate_event_envelope(event)
