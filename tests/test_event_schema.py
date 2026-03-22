import json
import pathlib
import sys
import unittest

PROJECT_ROOT = pathlib.Path(__file__).resolve().parents[1]
SRC_ROOT = PROJECT_ROOT / "src"
if str(SRC_ROOT) not in sys.path:
    sys.path.insert(0, str(SRC_ROOT))

from agentic_memory_fabric.events import validate_event_envelope


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
        schema_path = PROJECT_ROOT / "schemas" / "event-envelope.v0.json"
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

        event_types = schema["properties"]["event_type"]["enum"]
        self.assertTrue(
            {"created", "updated", "quarantined", "expired", "deleted"}.issubset(
                set(event_types)
            )
        )
        self.assertIn("signature", schema["properties"])
        self.assertIn("attestation", schema["properties"])

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
            "alg": "hmac-sha256",
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

    def test_validate_event_envelope_rejects_invalid_signature_algorithm(self) -> None:
        event = _valid_event()
        event["signature"] = {
            "alg": "rsa-sha256",
            "key_id": "dev-key",
            "sig": "YWJjZA==",
        }
        with self.assertRaisesRegex(ValueError, "signature.alg"):
            validate_event_envelope(event)
