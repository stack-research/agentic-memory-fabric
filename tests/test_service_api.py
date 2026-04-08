import pathlib
import sys
import tempfile
import unittest
import json

PROJECT_ROOT = pathlib.Path(__file__).resolve().parents[1]
SRC_ROOT = PROJECT_ROOT / "src"
if str(SRC_ROOT) not in sys.path:
    sys.path.insert(0, str(SRC_ROOT))
if str(pathlib.Path(__file__).resolve().parent) not in sys.path:
    sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

from agentic_memory_fabric.runtime import open_runtime
from agentic_memory_fabric.service import ServiceApp, run_http_server
from agentic_memory_fabric.crypto import KEY_STATUS_REVOKED, KeyMaterial, sign_event
from agentic_memory_fabric.events import EventEnvelope, canonical_payload_hash
from ed25519_utils import sign_event_ed25519

TENANT_HEADER = {"x-tenant-id": "tenant-alpha"}
AUTH_TOKENS = {
    "token-auditor": {
        "tenant_id": "tenant-alpha",
        "capabilities": ["override_retrieval_denials"],
        "role": "auditor",
    },
    "token-bravo": {
        "tenant_id": "tenant-bravo",
        "capabilities": ["override_retrieval_denials"],
        "role": "auditor",
    },
}


class ServiceApiTests(unittest.TestCase):
    def _signed_event(
        self,
        *,
        sequence: int = 1,
        event_id: str = "99999999-9999-4999-8999-999999999999",
        event_type: str = "created",
        previous_events: list[str] | None = None,
        attestation: dict | None = None,
        key_id: str = "dev-key",
        key: bytes = b"super-secret",
        payload: object | None = None,
        memory_id: str = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
        memory_class: str | None = None,
    ) -> dict:
        if previous_events is None:
            previous_events = []
        payload_hash = (
            canonical_payload_hash(payload)
            if payload is not None
            else "sha256:" + ("a" * 64)
        )
        event = EventEnvelope.from_dict(
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
                **({"memory_class": memory_class} if memory_class is not None else {}),
                **({"payload": payload} if payload is not None else {}),
            }
        )
        if attestation is not None:
            event = EventEnvelope.from_dict({**event.to_dict(), "attestation": attestation})
        event_dict = event.to_dict()
        event_dict["signature"] = {
            "alg": "hmac-sha256",
            "key_id": key_id,
            "sig": sign_event(event, key_id=key_id, key=key),
        }
        return event_dict

    def _ed25519_signed_event(self) -> tuple[dict, dict]:
        event = EventEnvelope.from_dict(
            {
                "event_id": "aaaaaaaa-1111-4111-8111-111111111111",
                "sequence": 1,
                "timestamp": {"wall_time": "2026-03-22T00:00:00Z", "tick": 1},
                "actor": {"id": "svc-memory", "kind": "service"},
                "tenant_id": "tenant-alpha",
                "memory_id": "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
                "event_type": "created",
                "previous_events": [],
                "payload_hash": "sha256:" + ("a" * 64),
            }
        )
        signature, jwk = sign_event_ed25519(event)
        event_dict = event.to_dict()
        event_dict["signature"] = {"alg": "ed25519", "key_id": "ed-key", "sig": signature}
        return event_dict, jwk

    def test_import_endpoint_emits_imported_events_only(self) -> None:
        app = ServiceApp()
        status, payload = app.handle_request(
            "POST",
            "/ingest/import",
            (
                b'{"records":[{"memory_id":"aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",'
                b'"payload":{"v":"x"},"source_id":"seed-1"}],'
                b'"actor":{"id":"migration-bot","kind":"service"},'
                b'"default_timestamp":"2026-03-22T00:00:00Z"}'
            ),
            headers=TENANT_HEADER,
        )
        self.assertEqual(status, 200)
        self.assertEqual(payload["count"], 1)
        self.assertEqual(payload["events"][0]["event_type"], "imported")

    def test_query_and_export_show_policy_denial_and_override(self) -> None:
        app = ServiceApp(auth_tokens=AUTH_TOKENS)
        app.handle_request(
            "POST",
            "/ingest/import",
            (
                b'{"records":[{"memory_id":"aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",'
                b'"payload":{"v":"x"},"source_id":"seed-1"}],'
                b'"actor":{"id":"migration-bot","kind":"service"},'
                b'"default_timestamp":"2026-03-22T00:00:00Z"}'
            ),
            headers=TENANT_HEADER,
        )

        status_default, payload_default = app.handle_request(
            "POST",
            "/query",
            b"{}",
            headers=TENANT_HEADER,
        )
        self.assertEqual(status_default, 200)
        self.assertTrue(payload_default["query_allowed"])
        self.assertEqual(payload_default["count"], 0)

        status_override, payload_override = app.handle_request(
            "POST",
            "/query",
            b'{"policy_context":{"capabilities":["override_retrieval_denials"]}}',
            headers={"x-tenant-id": "tenant-alpha", "x-auth-token": "token-auditor"},
        )
        self.assertEqual(status_override, 200)
        self.assertTrue(payload_override["query_allowed"])
        self.assertEqual(payload_override["count"], 1)
        self.assertEqual(
            payload_override["records"][0]["denial_reason"],
            "signature_missing_default_deny",
        )

        status_snapshot, payload_snapshot = app.handle_request(
            "POST",
            "/export/snapshot",
            b'{"policy_context":{"capabilities":["override_retrieval_denials"]}}',
            headers={"x-tenant-id": "tenant-alpha", "x-auth-token": "token-auditor"},
        )
        self.assertEqual(status_snapshot, 200)
        self.assertEqual(payload_snapshot["count"], 1)

    def test_query_uncertainty_gate_denies_and_allows_override(self) -> None:
        runtime = open_runtime(keyring={"dev-key": b"super-secret"})
        app = ServiceApp(runtime=runtime, auth_tokens=AUTH_TOKENS)
        app.handle_request(
            "POST",
            "/ingest/event",
            json.dumps({"event": self._signed_event()}).encode("utf-8"),
            headers=TENANT_HEADER,
        )
        status_low, payload_low = app.handle_request(
            "POST",
            "/query",
            b'{"policy_context":{"uncertainty_threshold":0.8,"uncertainty_score":0.4}}',
            headers=TENANT_HEADER,
        )
        self.assertEqual(status_low, 200)
        self.assertFalse(payload_low["query_allowed"])
        self.assertEqual(payload_low["query_denial_reason"], "uncertainty_below_threshold_default_deny")
        self.assertEqual(payload_low["count"], 0)

        status_override, payload_override = app.handle_request(
            "POST",
            "/query",
            (
                b'{"policy_context":{"uncertainty_threshold":0.8,"uncertainty_score":0.4,'
                b'"allow_low_uncertainty_override":true}}'
            ),
            headers={"x-tenant-id": "tenant-alpha", "x-auth-token": "token-auditor"},
        )
        self.assertEqual(status_override, 200)
        self.assertTrue(payload_override["query_allowed"])
        self.assertEqual(payload_override["query_denial_reason"], "uncertainty_below_threshold_default_deny")
        self.assertTrue(payload_override["query_override_used"])
        self.assertEqual(payload_override["count"], 1)

    def test_semantic_query_endpoint_returns_search_metadata(self) -> None:
        runtime = open_runtime(keyring={"dev-key": b"super-secret"})
        app = ServiceApp(runtime=runtime)
        app.handle_request(
            "POST",
            "/ingest/event",
            json.dumps(
                {
                    "event": self._signed_event(
                        payload={"topic": "memory fabric", "note": "semantic baseline"}
                    )
                }
            ).encode("utf-8"),
            headers=TENANT_HEADER,
        )
        status, payload = app.handle_request(
            "POST",
            "/query",
            b'{"query_text":"memory fabric"}',
            headers=TENANT_HEADER,
        )
        self.assertEqual(status, 200)
        self.assertEqual(payload["count"], 1)
        self.assertEqual(payload["records"][0]["retrieval_mode"], "lexical_v1")
        self.assertGreater(payload["records"][0]["retrieval_score"], 0.0)
        self.assertEqual(
            payload["records"][0]["indexed_event_id"],
            "99999999-9999-4999-8999-999999999999",
        )

    def test_graph_endpoints_and_query_expansion(self) -> None:
        runtime = open_runtime(keyring={"dev-key": b"super-secret"})
        app = ServiceApp(runtime=runtime)
        app.handle_request(
            "POST",
            "/ingest/event",
            json.dumps(
                {
                    "event": self._signed_event(
                        payload={"topic": "alpha memory"},
                        memory_id="aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
                    )
                }
            ).encode("utf-8"),
            headers=TENANT_HEADER,
        )
        app.handle_request(
            "POST",
            "/ingest/event",
            json.dumps(
                {
                    "event": self._signed_event(
                        sequence=2,
                        event_id="22222222-2222-4222-8222-222222222222",
                        payload={"topic": "bravo neighbor"},
                        memory_id="bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
                    )
                }
            ).encode("utf-8"),
            headers=TENANT_HEADER,
        )
        status_link, payload_link = app.handle_request(
            "POST",
            "/link",
            json.dumps(
                {
                    "source_memory_id": "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
                    "target_memory_id": "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
                    "actor": {"id": "svc-memory", "kind": "service"},
                    "event_id": "33333333-3333-4333-8333-333333333333",
                    "timestamp": {"wall_time": "2026-03-22T00:00:00Z", "tick": 3},
                }
            ).encode("utf-8"),
            headers=TENANT_HEADER,
        )
        self.assertEqual(status_link, 200)
        self.assertEqual(payload_link["event"]["event_type"], "linked")
        status_reinforce, payload_reinforce = app.handle_request(
            "POST",
            "/reinforce",
            json.dumps(
                {
                    "memory_id": "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
                    "related_memory_id": "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
                    "actor": {"id": "svc-memory", "kind": "service"},
                    "event_id": "44444444-4444-4444-8444-444444444444",
                    "timestamp": {"wall_time": "2026-03-22T00:00:00Z", "tick": 4},
                    "edge_weight": 2.0,
                }
            ).encode("utf-8"),
            headers=TENANT_HEADER,
        )
        self.assertEqual(status_reinforce, 200)
        self.assertEqual(payload_reinforce["record"]["reinforcement_score"], 2.0)
        status_conflict, payload_conflict = app.handle_request(
            "POST",
            "/conflict",
            json.dumps(
                {
                    "source_memory_id": "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
                    "target_memory_id": "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
                    "actor": {"id": "svc-memory", "kind": "service"},
                    "event_id": "55555555-5555-4555-8555-555555555555",
                    "timestamp": {"wall_time": "2026-03-22T00:00:00Z", "tick": 5},
                    "edge_weight": 1.5,
                }
            ).encode("utf-8"),
            headers=TENANT_HEADER,
        )
        self.assertEqual(status_conflict, 200)
        self.assertEqual(payload_conflict["event"]["event_type"], "conflicted")
        status_query, payload_query = app.handle_request(
            "POST",
            "/query",
            json.dumps({"query_text": "alpha", "graph_expand": True}).encode("utf-8"),
            headers=TENANT_HEADER,
        )
        self.assertEqual(status_query, 200)
        self.assertEqual(payload_query["count"], 2)
        self.assertEqual(payload_query["records"][0]["memory_id"], "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa")
        self.assertEqual(payload_query["records"][1]["memory_id"], "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb")
        self.assertEqual(payload_query["records"][1]["retrieval_mode"], "graph_expand_v1")

    def test_conflict_assessment_and_merge_endpoints(self) -> None:
        runtime = open_runtime(keyring={"dev-key": b"super-secret"})
        app = ServiceApp(runtime=runtime)
        app.handle_request(
            "POST",
            "/ingest/event",
            json.dumps(
                {
                    "event": self._signed_event(
                        payload={"topic": "alpha"},
                        memory_id="aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
                    )
                }
            ).encode("utf-8"),
            headers=TENANT_HEADER,
        )
        app.handle_request(
            "POST",
            "/ingest/event",
            json.dumps(
                {
                    "event": self._signed_event(
                        sequence=2,
                        event_id="22222222-2222-4222-8222-222222222222",
                        payload={"topic": "bravo"},
                        memory_id="bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
                    )
                }
            ).encode("utf-8"),
            headers=TENANT_HEADER,
        )
        app.handle_request(
            "POST",
            "/conflict",
            json.dumps(
                {
                    "source_memory_id": "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
                    "target_memory_id": "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
                    "actor": {"id": "svc-memory", "kind": "service"},
                    "event_id": "33333333-3333-4333-8333-333333333333",
                    "timestamp": {"wall_time": "2026-03-22T00:00:00Z", "tick": 3}
                }
            ).encode("utf-8"),
            headers=TENANT_HEADER,
        )
        status_assess, payload_assess = app.handle_request(
            "POST",
            "/assess-conflict",
            json.dumps(
                {
                    "memory_id": "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
                    "related_memory_id": "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
                }
            ).encode("utf-8"),
            headers=TENANT_HEADER,
        )
        self.assertEqual(status_assess, 200)
        self.assertTrue(payload_assess["resolvable"])
        status_propose, payload_propose = app.handle_request(
            "POST",
            "/merge/propose",
            json.dumps(
                {
                    "memory_ids": [
                        "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
                        "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
                    ],
                    "actor": {"id": "reviewer", "kind": "user"},
                    "payload": {"topic": "merged"},
                    "resolver_kind": "human_gate",
                    "merged_memory_id": "cccccccc-cccc-4ccc-8ccc-cccccccccccc",
                    "event_id": "44444444-4444-4444-8444-444444444444",
                    "timestamp": {"wall_time": "2026-03-22T00:00:00Z", "tick": 4}
                }
            ).encode("utf-8"),
            headers=TENANT_HEADER,
        )
        self.assertEqual(status_propose, 200)
        self.assertEqual(payload_propose["outcome"], "appended")
        self.assertEqual(payload_propose["event"]["event_type"], "merge_proposed")
        status_approve, payload_approve = app.handle_request(
            "POST",
            "/merge/approve",
            json.dumps(
                {
                    "memory_id": "cccccccc-cccc-4ccc-8ccc-cccccccccccc",
                    "actor": {"id": "reviewer", "kind": "user"},
                    "event_id": "55555555-5555-4555-8555-555555555555",
                    "timestamp": {"wall_time": "2026-03-22T00:00:00Z", "tick": 5},
                    "resolution_reason": "approved"
                }
            ).encode("utf-8"),
            headers=TENANT_HEADER,
        )
        self.assertEqual(status_approve, 200)
        self.assertEqual(payload_approve["event"]["event_type"], "merge_approved")
        status_query, payload_query = app.handle_request(
            "POST",
            "/query",
            json.dumps(
                {"structured_filter": {"merged_into_memory_id": "cccccccc-cccc-4ccc-8ccc-cccccccccccc"}}
            ).encode("utf-8"),
            headers=TENANT_HEADER,
        )
        self.assertEqual(status_query, 200)
        self.assertEqual(payload_query["count"], 2)

    def test_merge_reject_and_cross_tenant_denial_endpoints(self) -> None:
        runtime = open_runtime(keyring={"dev-key": b"super-secret"})
        app = ServiceApp(runtime=runtime)
        app.handle_request(
            "POST",
            "/ingest/event",
            json.dumps({"event": self._signed_event(payload={"topic": "alpha"})}).encode("utf-8"),
            headers=TENANT_HEADER,
        )
        app.handle_request(
            "POST",
            "/ingest/event",
            json.dumps(
                {
                    "event": self._signed_event(
                        sequence=2,
                        event_id="22222222-2222-4222-8222-222222222222",
                        payload={"topic": "bravo"},
                        memory_id="bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
                    )
                }
            ).encode("utf-8"),
            headers=TENANT_HEADER,
        )
        app.handle_request(
            "POST",
            "/conflict",
            json.dumps(
                {
                    "source_memory_id": "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
                    "target_memory_id": "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
                    "actor": {"id": "svc-memory", "kind": "service"},
                    "event_id": "33333333-3333-4333-8333-333333333333",
                    "timestamp": {"wall_time": "2026-03-22T00:00:00Z", "tick": 3}
                }
            ).encode("utf-8"),
            headers=TENANT_HEADER,
        )
        app.handle_request(
            "POST",
            "/merge/propose",
            json.dumps(
                {
                    "memory_ids": [
                        "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
                        "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
                    ],
                    "actor": {"id": "reviewer", "kind": "user"},
                    "payload": {"topic": "merged"},
                    "merged_memory_id": "cccccccc-cccc-4ccc-8ccc-cccccccccccc",
                    "event_id": "44444444-4444-4444-8444-444444444444",
                    "timestamp": {"wall_time": "2026-03-22T00:00:00Z", "tick": 4}
                }
            ).encode("utf-8"),
            headers=TENANT_HEADER,
        )
        status_reject, payload_reject = app.handle_request(
            "POST",
            "/merge/reject",
            json.dumps(
                {
                    "memory_id": "cccccccc-cccc-4ccc-8ccc-cccccccccccc",
                    "actor": {"id": "reviewer", "kind": "user"},
                    "event_id": "55555555-5555-4555-8555-555555555555",
                    "timestamp": {"wall_time": "2026-03-22T00:00:00Z", "tick": 5},
                    "resolution_reason": "rejected"
                }
            ).encode("utf-8"),
            headers=TENANT_HEADER,
        )
        self.assertEqual(status_reject, 200)
        self.assertEqual(payload_reject["event"]["event_type"], "merge_rejected")

        runtime = open_runtime(keyring={"dev-key": b"super-secret"})
        app = ServiceApp(runtime=runtime)
        app.handle_request(
            "POST",
            "/ingest/event",
            json.dumps({"event": self._signed_event(payload={"topic": "alpha"})}).encode("utf-8"),
            headers=TENANT_HEADER,
        )
        app.handle_request(
            "POST",
            "/ingest/event",
            json.dumps(
                {
                    "event": {
                        **self._signed_event(
                            sequence=2,
                            event_id="22222222-2222-4222-8222-222222222222",
                            payload={"topic": "bravo"},
                            memory_id="bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
                        ),
                        "tenant_id": "tenant-bravo",
                    }
                }
            ).encode("utf-8"),
            headers={"x-tenant-id": "tenant-bravo"},
        )
        status_denied, payload_denied = app.handle_request(
            "POST",
            "/merge/propose",
            json.dumps(
                {
                    "memory_ids": [
                        "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
                        "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
                    ],
                    "actor": {"id": "reviewer", "kind": "user"},
                    "payload": {"topic": "merged"},
                    "merged_memory_id": "cccccccc-cccc-4ccc-8ccc-cccccccccccc"
                }
            ).encode("utf-8"),
            headers=TENANT_HEADER,
        )
        self.assertEqual(status_denied, 200)
        self.assertEqual(payload_denied["outcome"], "denied")

    def test_semantic_query_over_imported_payloads(self) -> None:
        app = ServiceApp(auth_tokens=AUTH_TOKENS)
        app.handle_request(
            "POST",
            "/ingest/import",
            (
                b'{"records":[{"memory_id":"aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",'
                b'"payload":{"topic":"imported memory"},"source_id":"seed-1"}],'
                b'"actor":{"id":"migration-bot","kind":"service"},'
                b'"default_timestamp":"2026-03-22T00:00:00Z"}'
            ),
            headers=TENANT_HEADER,
        )
        status, payload = app.handle_request(
            "POST",
            "/query",
            b'{"query_text":"imported memory"}',
            headers={"x-tenant-id": "tenant-alpha", "x-auth-token": "token-auditor"},
        )
        self.assertEqual(status, 200)
        self.assertEqual(payload["count"], 1)
        self.assertTrue(payload["records"][0]["queryable_payload_present"])
        self.assertEqual(payload["records"][0]["retrieval_mode"], "lexical_v1")

    def test_peek_recall_and_reconsolidate_endpoints(self) -> None:
        runtime = open_runtime(keyring={"dev-key": b"super-secret"})
        app = ServiceApp(runtime=runtime)
        app.handle_request(
            "POST",
            "/ingest/event",
            json.dumps({"event": self._signed_event()}).encode("utf-8"),
            headers=TENANT_HEADER,
        )

        status_peek, payload_peek = app.handle_request(
            "POST",
            "/memory/aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa/peek",
            b"{}",
            headers=TENANT_HEADER,
        )
        self.assertEqual(status_peek, 200)
        self.assertEqual(payload_peek["record"]["version"], 1)

        status_recall, payload_recall = app.handle_request(
            "POST",
            "/memory/aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa/recall",
            json.dumps(
                {
                    "actor": {"id": "svc-memory", "kind": "service"},
                    "event_id": "11111111-2222-4222-8222-222222222222",
                    "timestamp": {"wall_time": "2026-03-22T00:00:00Z", "tick": 5},
                }
            ).encode("utf-8"),
            headers=TENANT_HEADER,
        )
        self.assertEqual(status_recall, 200)
        self.assertEqual(payload_recall["outcome"], "appended")
        self.assertEqual(payload_recall["record"]["version"], 1)
        self.assertEqual(payload_recall["record"]["recall_count"], 1)

        status_recon, payload_recon = app.handle_request(
            "POST",
            "/memory/aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa/reconsolidate",
            json.dumps(
                {
                    "actor": {"id": "svc-memory", "kind": "service"},
                    "payload_hash": "sha256:" + ("b" * 64),
                    "event_id": "11111111-3333-4333-8333-333333333333",
                    "timestamp": {"wall_time": "2026-03-22T00:00:00Z", "tick": 6},
                }
            ).encode("utf-8"),
            headers=TENANT_HEADER,
        )
        self.assertEqual(status_recon, 200)
        self.assertEqual(payload_recon["outcome"], "appended")
        self.assertEqual(payload_recon["record"]["version"], 2)
        self.assertEqual(payload_recon["record"]["reconsolidation_count"], 1)

    def test_assess_promotion_and_promote_endpoints(self) -> None:
        runtime = open_runtime(keyring={"dev-key": b"super-secret"})
        app = ServiceApp(runtime=runtime, auth_tokens=AUTH_TOKENS)
        app.handle_request(
            "POST",
            "/ingest/event",
            json.dumps(
                {"event": self._signed_event(payload={"topic": "episodic alpha"})}
            ).encode("utf-8"),
            headers=TENANT_HEADER,
        )

        status_assess, payload_assess = app.handle_request(
            "POST",
            "/memory/aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa/assess-promotion",
            b"{}",
            headers=TENANT_HEADER,
        )
        self.assertEqual(status_assess, 200)
        self.assertTrue(payload_assess["promotion_eligible"])
        self.assertEqual(payload_assess["memory_class"], "episodic")

        status_promote, payload_promote = app.handle_request(
            "POST",
            "/promote",
            (
                b'{"memory_ids":["aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"],'
                b'"actor":{"id":"auditor","kind":"service"},'
                b'"payload":{"topic":"semantic alpha"},'
                b'"promoted_memory_id":"bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",'
                b'"event_id":"22222222-2222-4222-8222-222222222222",'
                b'"timestamp":{"wall_time":"2026-03-22T00:00:00Z","tick":2}}'
            ),
            headers={"x-tenant-id": "tenant-alpha", "x-auth-token": "token-auditor"},
        )
        self.assertEqual(status_promote, 200)
        self.assertEqual(payload_promote["outcome"], "appended")
        self.assertEqual(payload_promote["event"]["event_type"], "promoted")
        self.assertEqual(payload_promote["event"]["memory_class"], "semantic")

    def test_promote_endpoint_denies_bad_source_without_override(self) -> None:
        app = ServiceApp()
        app.handle_request(
            "POST",
            "/ingest/import",
            (
                b'{"records":[{"memory_id":"aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",'
                b'"payload":{"topic":"unsigned source"},"source_id":"seed-1"}],'
                b'"actor":{"id":"migration-bot","kind":"service"},'
                b'"default_timestamp":"2026-03-22T00:00:00Z"}'
            ),
            headers=TENANT_HEADER,
        )
        status, payload = app.handle_request(
            "POST",
            "/promote",
            (
                b'{"memory_ids":["aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"],'
                b'"actor":{"id":"svc-memory","kind":"service"},'
                b'"payload":{"topic":"semantic denied"},'
                b'"promoted_memory_id":"bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",'
                b'"event_id":"22222222-2222-4222-8222-222222222222",'
                b'"timestamp":{"wall_time":"2026-03-22T00:00:00Z","tick":2}}'
            ),
            headers=TENANT_HEADER,
        )
        self.assertEqual(status, 200)
        self.assertEqual(payload["outcome"], "denied")
        self.assertIn("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", payload["source_denials"])

    def test_untrusted_policy_override_is_ignored(self) -> None:
        app = ServiceApp()
        app.handle_request(
            "POST",
            "/ingest/import",
            (
                b'{"records":[{"memory_id":"aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",'
                b'"payload":{"v":"x"},"source_id":"seed-1"}],'
                b'"actor":{"id":"migration-bot","kind":"service"},'
                b'"default_timestamp":"2026-03-22T00:00:00Z"}'
            ),
            headers=TENANT_HEADER,
        )
        status, payload = app.handle_request(
            "POST",
            "/query",
            b'{"policy_context":{"capabilities":["override_retrieval_denials"]}}',
            headers=TENANT_HEADER,
        )
        self.assertEqual(status, 200)
        self.assertTrue(payload["query_allowed"])
        self.assertEqual(payload["count"], 0)

    def test_explain_and_provenance_endpoints(self) -> None:
        app = ServiceApp(auth_tokens=AUTH_TOKENS)
        app.handle_request(
            "POST",
            "/ingest/import",
            (
                b'{"records":[{"memory_id":"aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",'
                b'"payload":{"v":"x"},"source_id":"seed-1"}],'
                b'"actor":{"id":"migration-bot","kind":"service"},'
                b'"default_timestamp":"2026-03-22T00:00:00Z"}'
            ),
            headers=TENANT_HEADER,
        )

        status_explain, payload_explain = app.handle_request(
            "GET",
            "/memory/aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa/explain",
            None,
            headers={"x-tenant-id": "tenant-alpha", "x-auth-token": "token-auditor"},
        )
        self.assertEqual(status_explain, 200)
        self.assertEqual(len(payload_explain["trace"]), 1)
        self.assertEqual(payload_explain["trace"][0]["event_type"], "imported")

        status_prov, payload_prov = app.handle_request(
            "POST",
            "/export/provenance",
            b"{}",
            headers=TENANT_HEADER,
        )
        self.assertEqual(status_prov, 200)
        self.assertEqual(payload_prov["count"], 1)

    def test_service_runtime_restarts_with_persistent_db(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = pathlib.Path(tmpdir) / "events.db"
            app_one = ServiceApp(runtime=open_runtime(db_path=db_path))
            app_two = None
            try:
                app_one.handle_request(
                    "POST",
                    "/ingest/import",
                    (
                        b'{"records":[{"memory_id":"aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",'
                        b'"payload":{"v":"x"},"source_id":"seed-1"}],'
                        b'"actor":{"id":"migration-bot","kind":"service"},'
                        b'"default_timestamp":"2026-03-22T00:00:00Z"}'
                    ),
                    headers=TENANT_HEADER,
                )

                app_two = ServiceApp(runtime=open_runtime(db_path=db_path), auth_tokens=AUTH_TOKENS)
                status, payload = app_two.handle_request(
                    "POST",
                    "/query",
                    b'{"policy_context":{"capabilities":["override_retrieval_denials"]}}',
                    headers={"x-tenant-id": "tenant-alpha", "x-auth-token": "token-auditor"},
                )
                self.assertEqual(status, 200)
                self.assertEqual(payload["count"], 1)
            finally:
                if app_two is not None:
                    app_two.close()
                app_one.close()

    def test_ingest_rejects_tenant_mismatch_with_trusted_auth(self) -> None:
        app = ServiceApp(auth_tokens=AUTH_TOKENS)
        with self.assertRaisesRegex(ValueError, "tenant mismatch"):
            app.handle_request(
                "POST",
                "/ingest/event",
                (
                    b'{"event":{"event_id":"11111111-1111-4111-8111-111111111111",'
                    b'"sequence":1,"timestamp":{"wall_time":"2026-03-22T00:00:00Z","tick":1},'
                    b'"actor":{"id":"svc-memory","kind":"service"},'
                    b'"tenant_id":"tenant-bravo",'
                    b'"memory_id":"aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",'
                    b'"event_type":"created","previous_events":[],"payload_hash":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}}'
                ),
                headers={"x-auth-token": "token-auditor", "x-tenant-id": "tenant-alpha"},
            )

    def test_cross_tenant_reads_are_denied(self) -> None:
        app = ServiceApp(auth_tokens=AUTH_TOKENS)
        app.handle_request(
            "POST",
            "/ingest/import",
            (
                b'{"records":[{"memory_id":"aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",'
                b'"payload":{"v":"x"},"source_id":"seed-1"}],'
                b'"actor":{"id":"migration-bot","kind":"service"},'
                b'"default_timestamp":"2026-03-22T00:00:00Z"}'
            ),
            headers=TENANT_HEADER,
        )
        status_query, payload_query = app.handle_request(
            "POST",
            "/query",
            b'{"policy_context":{"capabilities":["override_retrieval_denials"]}}',
            headers={"x-tenant-id": "tenant-bravo", "x-auth-token": "token-bravo"},
        )
        self.assertEqual(status_query, 200)
        self.assertEqual(payload_query["count"], 0)

        status_explain, payload_explain = app.handle_request(
            "GET",
            "/memory/aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa/explain",
            None,
            headers={"x-tenant-id": "tenant-bravo", "x-auth-token": "token-bravo"},
        )
        self.assertEqual(status_explain, 200)
        self.assertEqual(payload_explain["trace"], [])

    def test_run_http_server_rejects_runtime_and_db_path_together(self) -> None:
        with self.assertRaisesRegex(ValueError, "either runtime or db_path"):
            run_http_server(runtime=open_runtime(), db_path="events.db")

    def test_signed_ingest_with_keyring_allows_query_without_override(self) -> None:
        runtime = open_runtime(keyring={"dev-key": b"super-secret"})
        app = ServiceApp(runtime=runtime)
        status_ingest, _payload_ingest = app.handle_request(
            "POST",
            "/ingest/event",
            json_bytes({"event": self._signed_event()}),
            headers=TENANT_HEADER,
        )
        self.assertEqual(status_ingest, 200)
        status_query, payload_query = app.handle_request(
            "POST",
            "/query",
            b"{}",
            headers=TENANT_HEADER,
        )
        self.assertEqual(status_query, 200)
        self.assertEqual(payload_query["count"], 1)
        self.assertEqual(payload_query["records"][0]["signature_state"], "verified")

    def test_revoked_key_signature_denied_by_default(self) -> None:
        runtime = open_runtime(
            keyring={"dev-key": KeyMaterial(key=b"super-secret", status=KEY_STATUS_REVOKED)}
        )
        app = ServiceApp(runtime=runtime, auth_tokens=AUTH_TOKENS)
        app.handle_request(
            "POST",
            "/ingest/event",
            json_bytes({"event": self._signed_event()}),
            headers=TENANT_HEADER,
        )
        status_default, payload_default = app.handle_request(
            "POST",
            "/query",
            b"{}",
            headers=TENANT_HEADER,
        )
        self.assertEqual(status_default, 200)
        self.assertEqual(payload_default["count"], 0)
        status_override, payload_override = app.handle_request(
            "POST",
            "/query",
            b'{"policy_context":{"capabilities":["override_retrieval_denials"]}}',
            headers={"x-tenant-id": "tenant-alpha", "x-auth-token": "token-auditor"},
        )
        self.assertEqual(status_override, 200)
        self.assertEqual(payload_override["count"], 1)
        self.assertEqual(
            payload_override["records"][0]["denial_reason"],
            "signature_key_revoked_default_deny",
        )

    def test_query_after_second_write_returns_updated_version(self) -> None:
        runtime = open_runtime(keyring={"dev-key": b"super-secret"})
        app = ServiceApp(runtime=runtime)
        first_event = self._signed_event(
            sequence=1,
            event_id="11111111-1111-4111-8111-111111111111",
            event_type="created",
            previous_events=[],
        )
        second_event = self._signed_event(
            sequence=2,
            event_id="22222222-2222-4222-8222-222222222222",
            event_type="updated",
            previous_events=["11111111-1111-4111-8111-111111111111"],
        )
        app.handle_request("POST", "/ingest/event", json_bytes({"event": first_event}), headers=TENANT_HEADER)
        status_first, payload_first = app.handle_request(
            "POST",
            "/query",
            b"{}",
            headers=TENANT_HEADER,
        )
        self.assertEqual(status_first, 200)
        self.assertEqual(payload_first["count"], 1)
        self.assertEqual(payload_first["records"][0]["version"], 1)

        app.handle_request("POST", "/ingest/event", json_bytes({"event": second_event}), headers=TENANT_HEADER)
        status_second, payload_second = app.handle_request(
            "POST",
            "/query",
            b"{}",
            headers=TENANT_HEADER,
        )
        self.assertEqual(status_second, 200)
        self.assertEqual(payload_second["count"], 1)
        self.assertEqual(payload_second["records"][0]["version"], 2)

    def test_query_emits_runtime_and_http_audit_records(self) -> None:
        runtime_events: list[dict] = []
        http_events: list[dict] = []
        runtime = open_runtime(audit_sink=runtime_events.append)
        app = ServiceApp(runtime=runtime, audit_sink=http_events.append)
        app.handle_request(
            "POST",
            "/ingest/import",
            (
                b'{"records":[{"memory_id":"aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",'
                b'"payload":{"v":"x"},"source_id":"seed-1"}],'
                b'"actor":{"id":"migration-bot","kind":"service"},'
                b'"default_timestamp":"2026-03-22T00:00:00Z"}'
            ),
            headers=TENANT_HEADER,
        )
        status, payload = app.handle_request("POST", "/query", b"{}", headers=TENANT_HEADER)
        self.assertEqual(status, 200)
        self.assertEqual(payload["count"], 0)

        query_events = [event for event in runtime_events if event.get("type") == "memory.query"]
        self.assertEqual(len(query_events), 1)
        self.assertEqual(query_events[0]["allowed"], 0)
        self.assertEqual(query_events[0]["denied_by_reason"]["signature_missing_default_deny"], 1)

        http_query_events = [
            event
            for event in http_events
            if event.get("type") == "http.request" and event.get("http_route") == "/query"
        ]
        self.assertEqual(len(http_query_events), 1)
        self.assertEqual(http_query_events[0]["http_status"], 200)

    def test_export_endpoints_emit_runtime_and_http_audit_records(self) -> None:
        runtime_events: list[dict] = []
        http_events: list[dict] = []
        runtime = open_runtime(audit_sink=runtime_events.append)
        app = ServiceApp(runtime=runtime, audit_sink=http_events.append)
        app.handle_request(
            "POST",
            "/ingest/import",
            (
                b'{"records":[{"memory_id":"aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",'
                b'"payload":{"v":"x"},"source_id":"seed-1"}],'
                b'"actor":{"id":"migration-bot","kind":"service"},'
                b'"default_timestamp":"2026-03-22T00:00:00Z"}'
            ),
            headers=TENANT_HEADER,
        )

        status_snapshot, payload_snapshot = app.handle_request(
            "POST",
            "/export/snapshot",
            b"{}",
            headers=TENANT_HEADER,
        )
        self.assertEqual(status_snapshot, 200)
        self.assertEqual(payload_snapshot["artifact_type"], "memory_sbom_snapshot")

        status_prov_ok, payload_prov_ok = app.handle_request(
            "POST",
            "/export/provenance",
            b'{"memory_id":"aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"}',
            headers=TENANT_HEADER,
        )
        self.assertEqual(status_prov_ok, 200)
        self.assertEqual(payload_prov_ok["artifact_type"], "provenance_log_slice")

        status_prov_denied, payload_prov_denied = app.handle_request(
            "POST",
            "/export/provenance",
            b"{}",
            headers=None,
        )
        self.assertEqual(status_prov_denied, 200)
        self.assertEqual(payload_prov_denied["denial_reason"], "tenant_scope_required_default_deny")

        snapshot_events = [
            event for event in runtime_events if event.get("type") == "memory.export.snapshot"
        ]
        self.assertEqual(len(snapshot_events), 1)
        self.assertEqual(snapshot_events[0]["tenant_id"], "tenant-alpha")
        self.assertEqual(snapshot_events[0]["record_count"], payload_snapshot["count"])

        provenance_events = [
            event for event in runtime_events if event.get("type") == "memory.export.provenance"
        ]
        self.assertEqual(len(provenance_events), 2)
        self.assertTrue(any(event.get("load_strategy") == "memory_scoped" for event in provenance_events))
        self.assertTrue(any(event.get("load_strategy") == "denied" for event in provenance_events))

        http_export_events = [
            event
            for event in http_events
            if event.get("type") == "http.request"
            and event.get("http_route") in {"/export/snapshot", "/export/provenance"}
        ]
        self.assertEqual(len(http_export_events), 3)
        self.assertTrue(all(event.get("http_status") == 200 for event in http_export_events))

    def test_query_policy_context_attestation_gates_are_enforced(self) -> None:
        runtime = open_runtime(keyring={"dev-key": b"super-secret"})
        app = ServiceApp(runtime=runtime, auth_tokens=AUTH_TOKENS)
        status_ingest, _ = app.handle_request(
            "POST",
            "/ingest/event",
            json_bytes({"event": self._signed_event()}),
            headers=TENANT_HEADER,
        )
        self.assertEqual(status_ingest, 200)

        status_default, payload_default = app.handle_request(
            "POST",
            "/query",
            b"{}",
            headers=TENANT_HEADER,
        )
        self.assertEqual(status_default, 200)
        self.assertEqual(payload_default["count"], 1)

        status_attested, payload_attested = app.handle_request(
            "POST",
            "/query",
            b'{"policy_context":{"require_attestation":true}}',
            headers=TENANT_HEADER,
        )
        self.assertEqual(status_attested, 200)
        self.assertEqual(payload_attested["count"], 0)

        status_override, payload_override = app.handle_request(
            "POST",
            "/query",
            b'{"policy_context":{"require_attestation":true,"capabilities":["override_retrieval_denials"]}}',
            headers={"x-tenant-id": "tenant-alpha", "x-auth-token": "token-auditor"},
        )
        self.assertEqual(status_override, 200)
        self.assertEqual(payload_override["count"], 1)
        self.assertEqual(
            payload_override["records"][0]["denial_reason"],
            "attestation_required_default_deny",
        )

    def test_query_policy_context_attestation_issuer_gate_passthrough(self) -> None:
        runtime = open_runtime(keyring={"dev-key": b"super-secret"})
        app = ServiceApp(runtime=runtime, auth_tokens=AUTH_TOKENS)
        status_ingest, _ = app.handle_request(
            "POST",
            "/ingest/event",
            json_bytes(
                {
                    "event": self._signed_event(
                        attestation={
                            "issuer": "issuer-gamma",
                            "issued_at": "2026-03-22T00:00:00Z",
                            "trust_level": "high",
                        }
                    )
                }
            ),
            headers=TENANT_HEADER,
        )
        self.assertEqual(status_ingest, 200)

        status_denied, payload_denied = app.handle_request(
            "POST",
            "/query",
            b'{"policy_context":{"allowed_attestation_issuers":["issuer-alpha"]}}',
            headers=TENANT_HEADER,
        )
        self.assertEqual(status_denied, 200)
        self.assertEqual(payload_denied["count"], 0)

        status_override, payload_override = app.handle_request(
            "POST",
            "/query",
            b'{"policy_context":{"allowed_attestation_issuers":["issuer-alpha"],"capabilities":["override_retrieval_denials"]}}',
            headers={"x-tenant-id": "tenant-alpha", "x-auth-token": "token-auditor"},
        )
        self.assertEqual(status_override, 200)
        self.assertEqual(payload_override["count"], 1)
        self.assertEqual(
            payload_override["records"][0]["denial_reason"],
            "attestation_issuer_default_deny",
        )

    def test_ed25519_signed_ingest_with_jwk_keyring_allows_query(self) -> None:
        event_dict, jwk = self._ed25519_signed_event()
        runtime = open_runtime(keyring={"ed-key": jwk})
        app = ServiceApp(runtime=runtime)
        status_ingest, _payload_ingest = app.handle_request(
            "POST",
            "/ingest/event",
            json_bytes({"event": event_dict}),
            headers=TENANT_HEADER,
        )
        self.assertEqual(status_ingest, 200)
        status_query, payload_query = app.handle_request(
            "POST",
            "/query",
            b"{}",
            headers=TENANT_HEADER,
        )
        self.assertEqual(status_query, 200)
        self.assertEqual(payload_query["count"], 1)
        self.assertEqual(payload_query["records"][0]["signature_state"], "verified")


def json_bytes(value: dict) -> bytes:
    import json

    return json.dumps(value, sort_keys=True).encode("utf-8")
