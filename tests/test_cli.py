import io
import json
import pathlib
import sys
import tempfile
import unittest

PROJECT_ROOT = pathlib.Path(__file__).resolve().parents[1]
SRC_ROOT = PROJECT_ROOT / "src"
if str(SRC_ROOT) not in sys.path:
    sys.path.insert(0, str(SRC_ROOT))

from agentic_memory_fabric.cli import run_cli
from agentic_memory_fabric.crypto import sign_event
from agentic_memory_fabric.events import EventEnvelope


class CliTests(unittest.TestCase):
    def _signed_event_json(
        self,
        *,
        sequence: int = 1,
        event_id: str = "99999999-9999-4999-8999-999999999999",
        event_type: str = "created",
        previous_events: list[str] | None = None,
    ) -> str:
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
            "key_id": "dev-key",
            "sig": sign_event(event, key_id="dev-key", key=b"super-secret"),
        }
        return json.dumps(event_dict, sort_keys=True)

    def test_cli_contracts_and_deterministic_json_output(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            state_file = str(pathlib.Path(tmpdir) / "state.json")

            out = io.StringIO()
            rc = run_cli(
                [
                    "--state-file",
                    state_file,
                    "--tenant-id",
                    "tenant-alpha",
                    "import-records",
                    "--records-json",
                    (
                        '[{"memory_id":"aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",'
                        '"payload":{"v":"x"},"source_id":"seed-1"}]'
                    ),
                    "--actor-json",
                    '{"id":"migration-bot","kind":"service"}',
                    "--default-timestamp",
                    "2026-03-22T00:00:00Z",
                ],
                stdout=out,
            )
            self.assertEqual(rc, 0)
            imported = json.loads(out.getvalue())
            self.assertEqual(imported["count"], 1)
            self.assertEqual(imported["events"][0]["event_type"], "imported")

            out_default = io.StringIO()
            run_cli(
                ["--state-file", state_file, "--tenant-id", "tenant-alpha", "query"],
                stdout=out_default,
            )
            query_default = json.loads(out_default.getvalue())
            self.assertEqual(query_default["count"], 0)

            out_override = io.StringIO()
            run_cli(
                [
                    "--state-file",
                    state_file,
                    "--tenant-id",
                    "tenant-alpha",
                    "--capabilities-json",
                    '["override_retrieval_denials"]',
                    "query",
                ],
                stdout=out_override,
            )
            query_override = json.loads(out_override.getvalue())
            self.assertEqual(query_override["count"], 1)

            out_explain = io.StringIO()
            run_cli(
                [
                    "--state-file",
                    state_file,
                    "--tenant-id",
                    "tenant-alpha",
                    "--capabilities-json",
                    '["override_retrieval_denials"]',
                    "explain",
                    "--memory-id",
                    "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
                ],
                stdout=out_explain,
            )
            explain_payload = json.loads(out_explain.getvalue())
            self.assertEqual(explain_payload["trace"][0]["event_type"], "imported")

            out_prov_a = io.StringIO()
            run_cli(
                ["--state-file", state_file, "--tenant-id", "tenant-alpha", "export-provenance"],
                stdout=out_prov_a,
            )
            out_prov_b = io.StringIO()
            run_cli(
                ["--state-file", state_file, "--tenant-id", "tenant-alpha", "export-provenance"],
                stdout=out_prov_b,
            )
            self.assertEqual(out_prov_a.getvalue(), out_prov_b.getvalue())

    def test_cli_db_persists_across_invocations(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            db_file = str(pathlib.Path(tmpdir) / "events.db")

            out_import = io.StringIO()
            rc = run_cli(
                [
                    "--db",
                    db_file,
                    "--tenant-id",
                    "tenant-alpha",
                    "import-records",
                    "--records-json",
                    (
                        '[{"memory_id":"aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",'
                        '"payload":{"v":"x"},"source_id":"seed-1"}]'
                    ),
                    "--actor-json",
                    '{"id":"migration-bot","kind":"service"}',
                    "--default-timestamp",
                    "2026-03-22T00:00:00Z",
                ],
                stdout=out_import,
            )
            self.assertEqual(rc, 0)
            imported = json.loads(out_import.getvalue())
            self.assertEqual(imported["count"], 1)

            out_query = io.StringIO()
            run_cli(
                [
                    "--db",
                    db_file,
                    "--tenant-id",
                    "tenant-alpha",
                    "--capabilities-json",
                    '["override_retrieval_denials"]',
                    "query",
                ],
                stdout=out_query,
            )
            query_payload = json.loads(out_query.getvalue())
            self.assertEqual(query_payload["count"], 1)

            out_prov = io.StringIO()
            run_cli(
                ["--db", db_file, "--tenant-id", "tenant-alpha", "export-provenance"],
                stdout=out_prov,
            )
            provenance = json.loads(out_prov.getvalue())
            self.assertEqual(provenance["count"], 1)

    def test_cli_signed_ingest_with_keyring_allows_default_query(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            state_file = str(pathlib.Path(tmpdir) / "state.json")
            out_ingest = io.StringIO()
            rc = run_cli(
                [
                    "--state-file",
                    state_file,
                    "--tenant-id",
                    "tenant-alpha",
                    "--keyring-json",
                    '{"dev-key":{"key":"super-secret","status":"active"}}',
                    "ingest-event",
                    "--event-json",
                    self._signed_event_json(),
                ],
                stdout=out_ingest,
            )
            self.assertEqual(rc, 0)
            out_query = io.StringIO()
            run_cli(
                [
                    "--state-file",
                    state_file,
                    "--tenant-id",
                    "tenant-alpha",
                    "--keyring-json",
                    '{"dev-key":{"key":"super-secret","status":"active"}}',
                    "query",
                ],
                stdout=out_query,
            )
            payload = json.loads(out_query.getvalue())
            self.assertEqual(payload["count"], 1)
            self.assertEqual(payload["records"][0]["signature_state"], "verified")

    def test_cli_db_query_updates_after_second_signed_ingest(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            db_file = str(pathlib.Path(tmpdir) / "events.db")
            keyring_json = '{"dev-key":{"key":"super-secret","status":"active"}}'

            run_cli(
                [
                    "--db",
                    db_file,
                    "--tenant-id",
                    "tenant-alpha",
                    "--keyring-json",
                    keyring_json,
                    "ingest-event",
                    "--event-json",
                    self._signed_event_json(
                        sequence=1,
                        event_id="11111111-1111-4111-8111-111111111111",
                        event_type="created",
                        previous_events=[],
                    ),
                ],
                stdout=io.StringIO(),
            )

            out_first = io.StringIO()
            run_cli(
                [
                    "--db",
                    db_file,
                    "--tenant-id",
                    "tenant-alpha",
                    "--keyring-json",
                    keyring_json,
                    "query",
                ],
                stdout=out_first,
            )
            first_payload = json.loads(out_first.getvalue())
            self.assertEqual(first_payload["count"], 1)
            self.assertEqual(first_payload["records"][0]["version"], 1)

            run_cli(
                [
                    "--db",
                    db_file,
                    "--tenant-id",
                    "tenant-alpha",
                    "--keyring-json",
                    keyring_json,
                    "ingest-event",
                    "--event-json",
                    self._signed_event_json(
                        sequence=2,
                        event_id="22222222-2222-4222-8222-222222222222",
                        event_type="updated",
                        previous_events=["11111111-1111-4111-8111-111111111111"],
                    ),
                ],
                stdout=io.StringIO(),
            )

            out_second = io.StringIO()
            run_cli(
                [
                    "--db",
                    db_file,
                    "--tenant-id",
                    "tenant-alpha",
                    "--keyring-json",
                    keyring_json,
                    "query",
                ],
                stdout=out_second,
            )
            second_payload = json.loads(out_second.getvalue())
            self.assertEqual(second_payload["count"], 1)
            self.assertEqual(second_payload["records"][0]["version"], 2)
