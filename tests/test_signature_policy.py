import pathlib
import sys
import unittest

PROJECT_ROOT = pathlib.Path(__file__).resolve().parents[1]
SRC_ROOT = PROJECT_ROOT / "src"
if str(SRC_ROOT) not in sys.path:
    sys.path.insert(0, str(SRC_ROOT))

from agentic_memory_fabric.crypto import KEY_STATUS_REVOKED, KeyMaterial, sign_event, verify_event_signature
from agentic_memory_fabric.events import EventEnvelope
from agentic_memory_fabric.log import AppendOnlyEventLog
from agentic_memory_fabric.policy import OVERRIDE_CAPABILITY, PolicyContext
from agentic_memory_fabric.replay import replay_events
from agentic_memory_fabric.retrieval import get


def _base_event_dict() -> dict:
    return {
        "event_id": "11111111-1111-4111-8111-111111111111",
        "sequence": 1,
        "timestamp": {"wall_time": "2026-03-22T00:00:00Z", "tick": 1},
        "actor": {"id": "svc-memory", "kind": "service"},
        "tenant_id": "tenant-alpha",
        "memory_id": "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
        "event_type": "created",
        "previous_events": [],
        "payload_hash": "sha256:" + ("a" * 64),
    }


class SignaturePolicyTests(unittest.TestCase):
    def _resolver(self, key_id: str) -> bytes | None:
        keys = {"dev-key": b"super-secret"}
        return keys.get(key_id)

    def _signed_event(self, *, key_id: str = "dev-key", key: bytes = b"super-secret") -> EventEnvelope:
        unsigned_event = EventEnvelope.from_dict(_base_event_dict())
        sig = sign_event(unsigned_event, key_id=key_id, key=key)
        signed_dict = unsigned_event.to_dict()
        signed_dict["signature"] = {"alg": "hmac-sha256", "key_id": key_id, "sig": sig}
        return EventEnvelope.from_dict(signed_dict)

    def _state_from_log(self, event: EventEnvelope) -> dict:
        log = AppendOnlyEventLog()
        log.append(event, signature_verifier=lambda evt: verify_event_signature(evt, key_resolver=self._resolver))
        return replay_events(log.all_events(), signature_states=log.signature_states())

    def test_verified_signature_allows_retrieval(self) -> None:
        state_map = self._state_from_log(self._signed_event())
        record = get(
            "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
            state_map,
            PolicyContext(tenant_id="tenant-alpha"),
        )
        self.assertIsNotNone(record)
        assert record is not None
        self.assertEqual(record.signature_state, "verified")

    def test_unsigned_and_invalid_signatures_denied_by_default(self) -> None:
        unsigned_state = self._state_from_log(EventEnvelope.from_dict(_base_event_dict()))
        self.assertIsNone(
            get("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", unsigned_state, PolicyContext())
        )
        self.assertIsNone(
            get(
                "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
                unsigned_state,
                PolicyContext(tenant_id="tenant-alpha"),
            )
        )

        invalid_dict = _base_event_dict()
        invalid_dict["signature"] = {
            "alg": "hmac-sha256",
            "key_id": "dev-key",
            "sig": "d3Jvbmctc2ln",
        }
        invalid_event = EventEnvelope.from_dict(invalid_dict)
        invalid_state = self._state_from_log(invalid_event)
        self.assertIsNone(
            get("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", invalid_state, PolicyContext())
        )
        self.assertIsNone(
            get(
                "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
                invalid_state,
                PolicyContext(tenant_id="tenant-alpha"),
            )
        )

    def test_override_allows_unsigned_with_explicit_reason(self) -> None:
        unsigned_state = self._state_from_log(EventEnvelope.from_dict(_base_event_dict()))
        record = get(
            "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
            unsigned_state,
            PolicyContext(
                capabilities=frozenset({OVERRIDE_CAPABILITY}),
                tenant_id="tenant-alpha",
                trusted_subject=True,
            ),
        )
        self.assertIsNotNone(record)
        assert record is not None
        self.assertEqual(record.denial_reason, "signature_missing_default_deny")
        self.assertTrue(record.override_used)

    def test_tampered_event_fails_verification_deterministically(self) -> None:
        signed_event = self._signed_event()
        tampered_dict = signed_event.to_dict()
        tampered_dict["payload_hash"] = "sha256:" + ("b" * 64)
        tampered_event = EventEnvelope.from_dict(tampered_dict)
        first = verify_event_signature(tampered_event, key_resolver=self._resolver)
        second = verify_event_signature(tampered_event, key_resolver=self._resolver)
        self.assertEqual(first, "invalid")
        self.assertEqual(second, "invalid")

    def test_rotation_window_with_two_active_keys_verifies(self) -> None:
        event_old = self._signed_event(key_id="old-key", key=b"old-secret")
        event_new = self._signed_event(key_id="new-key", key=b"new-secret")

        def resolver(key_id: str) -> bytes | None:
            keys = {"old-key": b"old-secret", "new-key": b"new-secret"}
            return keys.get(key_id)

        self.assertEqual(verify_event_signature(event_old, key_resolver=resolver), "verified")
        self.assertEqual(verify_event_signature(event_new, key_resolver=resolver), "verified")

    def test_missing_and_revoked_keys_have_distinct_denial_reasons(self) -> None:
        signed_event = self._signed_event(key_id="dev-key", key=b"super-secret")

        missing_state = verify_event_signature(signed_event, key_resolver=lambda _key_id: None)
        self.assertEqual(missing_state, "key_missing")

        revoked_state = verify_event_signature(
            signed_event,
            key_resolver=lambda _key_id: KeyMaterial(key=b"super-secret", status=KEY_STATUS_REVOKED),
        )
        self.assertEqual(revoked_state, "revoked")
