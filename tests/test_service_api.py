import pathlib
import sys
import tempfile
import unittest

PROJECT_ROOT = pathlib.Path(__file__).resolve().parents[1]
SRC_ROOT = PROJECT_ROOT / "src"
if str(SRC_ROOT) not in sys.path:
    sys.path.insert(0, str(SRC_ROOT))

from agentic_memory_fabric.runtime import open_runtime
from agentic_memory_fabric.service import ServiceApp, run_http_server
from agentic_memory_fabric.crypto import KEY_STATUS_REVOKED, KeyMaterial, sign_event
from agentic_memory_fabric.events import EventEnvelope

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
        key_id: str = "dev-key",
        key: bytes = b"super-secret",
    ) -> dict:
        if previous_events is None:
            previous_events = []
        event = EventEnvelope.from_dict(
            {
                "event_id": event_id,
                "sequence": sequence,
                "timestamp": {"wall_time": "2026-03-22T00:00:00Z", "tick": sequence},
                "actor": {"id": "svc-memory", "kind": "service"},
                "tenant_id": "tenant-alpha",
                "memory_id": "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
                "event_type": event_type,
                "previous_events": previous_events,
                "payload_hash": "sha256:" + ("a" * 64),
            }
        )
        event_dict = event.to_dict()
        event_dict["signature"] = {
            "alg": "hmac-sha256",
            "key_id": key_id,
            "sig": sign_event(event, key_id=key_id, key=key),
        }
        return event_dict

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


def json_bytes(value: dict) -> bytes:
    import json

    return json.dumps(value, sort_keys=True).encode("utf-8")
