import pathlib
import sys
import unittest

PROJECT_ROOT = pathlib.Path(__file__).resolve().parents[1]
SRC_ROOT = PROJECT_ROOT / "src"
if str(SRC_ROOT) not in sys.path:
    sys.path.insert(0, str(SRC_ROOT))

from agentic_memory_fabric.service import ServiceApp


class ServiceApiTests(unittest.TestCase):
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
        )
        self.assertEqual(status, 200)
        self.assertEqual(payload["count"], 1)
        self.assertEqual(payload["events"][0]["event_type"], "imported")

    def test_query_and_export_show_policy_denial_and_override(self) -> None:
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
        )

        status_default, payload_default = app.handle_request("POST", "/query", b"{}")
        self.assertEqual(status_default, 200)
        self.assertEqual(payload_default["count"], 0)

        status_override, payload_override = app.handle_request(
            "POST",
            "/query",
            b'{"policy_context":{"capabilities":["override_retrieval_denials"]}}',
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
        )
        self.assertEqual(status_snapshot, 200)
        self.assertEqual(payload_snapshot["count"], 1)

    def test_explain_and_provenance_endpoints(self) -> None:
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
        )

        status_explain, payload_explain = app.handle_request(
            "GET", "/memory/aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa/explain", None
        )
        self.assertEqual(status_explain, 200)
        self.assertEqual(len(payload_explain["trace"]), 1)
        self.assertEqual(payload_explain["trace"][0]["event_type"], "imported")

        status_prov, payload_prov = app.handle_request("POST", "/export/provenance", b"{}")
        self.assertEqual(status_prov, 200)
        self.assertEqual(payload_prov["count"], 1)
