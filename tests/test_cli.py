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
if str(pathlib.Path(__file__).resolve().parent) not in sys.path:
    sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

from agentic_memory_fabric.cli import run_cli
from agentic_memory_fabric.crypto import sign_event
from agentic_memory_fabric.events import EventEnvelope, canonical_payload_hash
from ed25519_utils import sign_event_ed25519


class CliTests(unittest.TestCase):
    def _signed_event_json(
        self,
        *,
        sequence: int = 1,
        event_id: str = "99999999-9999-4999-8999-999999999999",
        event_type: str = "created",
        previous_events: list[str] | None = None,
        attestation: dict | None = None,
        payload: object | None = None,
        memory_id: str = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
        memory_class: str | None = None,
    ) -> str:
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
        event_dict = event.to_dict()
        if attestation is not None:
            event_dict["attestation"] = attestation
            event = EventEnvelope.from_dict(event_dict)
            event_dict = event.to_dict()
        event_dict["signature"] = {
            "alg": "hmac-sha256",
            "key_id": "dev-key",
            "sig": sign_event(event, key_id="dev-key", key=b"super-secret"),
        }
        return json.dumps(event_dict, sort_keys=True)

    def _ed25519_signed_event_json(self) -> tuple[str, str]:
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
        keyring_json = json.dumps({"ed-key": jwk}, sort_keys=True)
        return json.dumps(event_dict, sort_keys=True), keyring_json

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
            self.assertTrue(query_default["query_allowed"])
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
            self.assertTrue(query_override["query_allowed"])
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
            self.assertTrue(payload["query_allowed"])
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
            self.assertTrue(first_payload["query_allowed"])
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
            self.assertTrue(second_payload["query_allowed"])
            self.assertEqual(second_payload["count"], 1)
            self.assertEqual(second_payload["records"][0]["version"], 2)

    def test_cli_writes_audit_jsonl_records(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            state_file = str(pathlib.Path(tmpdir) / "state.json")
            audit_file = pathlib.Path(tmpdir) / "audit.jsonl"
            run_cli(
                [
                    "--state-file",
                    state_file,
                    "--tenant-id",
                    "tenant-alpha",
                    "--audit-jsonl",
                    str(audit_file),
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
                stdout=io.StringIO(),
            )
            run_cli(
                [
                    "--state-file",
                    state_file,
                    "--tenant-id",
                    "tenant-alpha",
                    "--audit-jsonl",
                    str(audit_file),
                    "query",
                ],
                stdout=io.StringIO(),
            )
            run_cli(
                [
                    "--state-file",
                    state_file,
                    "--tenant-id",
                    "tenant-alpha",
                    "--audit-jsonl",
                    str(audit_file),
                    "export-snapshot",
                ],
                stdout=io.StringIO(),
            )
            run_cli(
                [
                    "--state-file",
                    state_file,
                    "--tenant-id",
                    "tenant-alpha",
                    "--audit-jsonl",
                    str(audit_file),
                    "export-provenance",
                ],
                stdout=io.StringIO(),
            )
            lines = [line for line in audit_file.read_text(encoding="utf-8").splitlines() if line.strip()]
            parsed = [json.loads(line) for line in lines]
            self.assertTrue(any(event.get("type") == "memory.query" for event in parsed))
            self.assertTrue(any(event.get("type") == "memory.export.snapshot" for event in parsed))
            self.assertTrue(any(event.get("type") == "memory.export.provenance" for event in parsed))

    def test_cli_query_policy_context_attestation_gate(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            state_file = str(pathlib.Path(tmpdir) / "state.json")
            keyring_json = '{"dev-key":{"key":"super-secret","status":"active"}}'
            run_cli(
                [
                    "--state-file",
                    state_file,
                    "--tenant-id",
                    "tenant-alpha",
                    "--keyring-json",
                    keyring_json,
                    "ingest-event",
                    "--event-json",
                    self._signed_event_json(),
                ],
                stdout=io.StringIO(),
            )

            out_denied = io.StringIO()
            run_cli(
                [
                    "--state-file",
                    state_file,
                    "--tenant-id",
                    "tenant-alpha",
                    "--keyring-json",
                    keyring_json,
                    "query",
                    "--policy-json",
                    '{"require_attestation": true}',
                ],
                stdout=out_denied,
            )
            denied_payload = json.loads(out_denied.getvalue())
            self.assertTrue(denied_payload["query_allowed"])
            self.assertEqual(denied_payload["count"], 0)

            out_override = io.StringIO()
            run_cli(
                [
                    "--state-file",
                    state_file,
                    "--tenant-id",
                    "tenant-alpha",
                    "--keyring-json",
                    keyring_json,
                    "--capabilities-json",
                    '["override_retrieval_denials"]',
                    "query",
                    "--policy-json",
                    '{"require_attestation": true}',
                ],
                stdout=out_override,
            )
            override_payload = json.loads(out_override.getvalue())
            self.assertTrue(override_payload["query_allowed"])
            self.assertEqual(override_payload["count"], 1)
            self.assertEqual(
                override_payload["records"][0]["denial_reason"],
                "attestation_required_default_deny",
            )

    def test_cli_query_policy_context_attestation_issuer_gate(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            state_file = str(pathlib.Path(tmpdir) / "state.json")
            keyring_json = '{"dev-key":{"key":"super-secret","status":"active"}}'
            run_cli(
                [
                    "--state-file",
                    state_file,
                    "--tenant-id",
                    "tenant-alpha",
                    "--keyring-json",
                    keyring_json,
                    "ingest-event",
                    "--event-json",
                    self._signed_event_json(
                        attestation={
                            "issuer": "issuer-gamma",
                            "issued_at": "2026-03-22T00:00:00Z",
                            "trust_level": "high",
                        }
                    ),
                ],
                stdout=io.StringIO(),
            )

            out_denied = io.StringIO()
            run_cli(
                [
                    "--state-file",
                    state_file,
                    "--tenant-id",
                    "tenant-alpha",
                    "--keyring-json",
                    keyring_json,
                    "query",
                    "--policy-json",
                    '{"allowed_attestation_issuers": ["issuer-alpha"]}',
                ],
                stdout=out_denied,
            )
            denied_payload = json.loads(out_denied.getvalue())
            self.assertTrue(denied_payload["query_allowed"])
            self.assertEqual(denied_payload["count"], 0)

            out_override = io.StringIO()
            run_cli(
                [
                    "--state-file",
                    state_file,
                    "--tenant-id",
                    "tenant-alpha",
                    "--keyring-json",
                    keyring_json,
                    "--capabilities-json",
                    '["override_retrieval_denials"]',
                    "query",
                    "--policy-json",
                    '{"allowed_attestation_issuers": ["issuer-alpha"]}',
                ],
                stdout=out_override,
            )
            override_payload = json.loads(out_override.getvalue())
            self.assertTrue(override_payload["query_allowed"])
            self.assertEqual(override_payload["count"], 1)
            self.assertEqual(
                override_payload["records"][0]["denial_reason"],
                "attestation_issuer_default_deny",
            )

    def test_cli_query_uncertainty_gate(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            state_file = str(pathlib.Path(tmpdir) / "state.json")
            keyring_json = '{"dev-key":{"key":"super-secret","status":"active"}}'
            run_cli(
                [
                    "--state-file",
                    state_file,
                    "--tenant-id",
                    "tenant-alpha",
                    "--keyring-json",
                    keyring_json,
                    "ingest-event",
                    "--event-json",
                    self._signed_event_json(),
                ],
                stdout=io.StringIO(),
            )

            out_missing = io.StringIO()
            run_cli(
                [
                    "--state-file",
                    state_file,
                    "--tenant-id",
                    "tenant-alpha",
                    "--keyring-json",
                    keyring_json,
                    "query",
                    "--policy-json",
                    '{"uncertainty_threshold": 0.8}',
                ],
                stdout=out_missing,
            )
            missing_payload = json.loads(out_missing.getvalue())
            self.assertFalse(missing_payload["query_allowed"])
            self.assertEqual(
                missing_payload["query_denial_reason"],
                "uncertainty_signal_required_default_deny",
            )
            self.assertEqual(missing_payload["count"], 0)

            out_override = io.StringIO()
            run_cli(
                [
                    "--state-file",
                    state_file,
                    "--tenant-id",
                    "tenant-alpha",
                    "--keyring-json",
                    keyring_json,
                    "--capabilities-json",
                    '["override_retrieval_denials"]',
                    "query",
                    "--policy-json",
                    '{"uncertainty_threshold": 0.8, "uncertainty_score": 0.4, "allow_low_uncertainty_override": true}',
                ],
                stdout=out_override,
            )
            override_payload = json.loads(out_override.getvalue())
            self.assertTrue(override_payload["query_allowed"])
            self.assertTrue(override_payload["query_override_used"])
            self.assertEqual(
                override_payload["query_denial_reason"],
                "uncertainty_below_threshold_default_deny",
            )
            self.assertEqual(override_payload["count"], 1)

    def test_cli_semantic_query_returns_search_metadata(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            state_file = str(pathlib.Path(tmpdir) / "state.json")
            keyring_json = '{"dev-key":{"key":"super-secret","status":"active"}}'
            run_cli(
                [
                    "--state-file",
                    state_file,
                    "--tenant-id",
                    "tenant-alpha",
                    "--keyring-json",
                    keyring_json,
                    "ingest-event",
                    "--event-json",
                    self._signed_event_json(
                        payload={"topic": "memory fabric", "note": "semantic query"}
                    ),
                ],
                stdout=io.StringIO(),
            )
            out_query = io.StringIO()
            run_cli(
                [
                    "--state-file",
                    state_file,
                    "--tenant-id",
                    "tenant-alpha",
                    "--keyring-json",
                    keyring_json,
                    "query",
                    "--query-text",
                    "memory fabric",
                    "--structured-filter-json",
                    '{"queryable_payload_present": true}',
                ],
                stdout=out_query,
            )
            payload = json.loads(out_query.getvalue())
            self.assertEqual(payload["count"], 1)
            self.assertEqual(payload["records"][0]["retrieval_mode"], "lexical_v1")
            self.assertGreater(payload["records"][0]["retrieval_score"], 0.0)

    def test_cli_graph_commands_and_query_expansion(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            state_file = str(pathlib.Path(tmpdir) / "state.json")
            keyring_json = '{"dev-key":{"key":"super-secret","status":"active"}}'
            run_cli(
                [
                    "--state-file",
                    state_file,
                    "--tenant-id",
                    "tenant-alpha",
                    "--keyring-json",
                    keyring_json,
                    "ingest-event",
                    "--event-json",
                    self._signed_event_json(
                        payload={"topic": "alpha memory"},
                        memory_id="aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
                    ),
                ],
                stdout=io.StringIO(),
            )
            run_cli(
                [
                    "--state-file",
                    state_file,
                    "--tenant-id",
                    "tenant-alpha",
                    "--keyring-json",
                    keyring_json,
                    "ingest-event",
                    "--event-json",
                    self._signed_event_json(
                        sequence=2,
                        event_id="22222222-2222-4222-8222-222222222222",
                        payload={"topic": "bravo neighbor"},
                        memory_id="bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
                    ),
                ],
                stdout=io.StringIO(),
            )
            out_link = io.StringIO()
            run_cli(
                [
                    "--state-file",
                    state_file,
                    "--tenant-id",
                    "tenant-alpha",
                    "--keyring-json",
                    keyring_json,
                    "link",
                    "--source-memory-id",
                    "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
                    "--target-memory-id",
                    "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
                    "--actor-json",
                    '{"id":"svc-memory","kind":"service"}',
                    "--event-id",
                    "33333333-3333-4333-8333-333333333333",
                    "--timestamp-json",
                    '{"wall_time":"2026-03-22T00:00:00Z","tick":3}',
                ],
                stdout=out_link,
            )
            link_payload = json.loads(out_link.getvalue())
            self.assertEqual(link_payload["event"]["event_type"], "linked")
            out_reinforce = io.StringIO()
            run_cli(
                [
                    "--state-file",
                    state_file,
                    "--tenant-id",
                    "tenant-alpha",
                    "--keyring-json",
                    keyring_json,
                    "reinforce",
                    "--memory-id",
                    "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
                    "--related-memory-id",
                    "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
                    "--actor-json",
                    '{"id":"svc-memory","kind":"service"}',
                    "--event-id",
                    "44444444-4444-4444-8444-444444444444",
                    "--timestamp-json",
                    '{"wall_time":"2026-03-22T00:00:00Z","tick":4}',
                    "--edge-weight",
                    "2.0",
                ],
                stdout=out_reinforce,
            )
            reinforce_payload = json.loads(out_reinforce.getvalue())
            self.assertEqual(reinforce_payload["record"]["reinforcement_score"], 2.0)
            out_query = io.StringIO()
            run_cli(
                [
                    "--state-file",
                    state_file,
                    "--tenant-id",
                    "tenant-alpha",
                    "--keyring-json",
                    keyring_json,
                    "query",
                    "--query-text",
                    "alpha",
                    "--graph-expand",
                ],
                stdout=out_query,
            )
            payload = json.loads(out_query.getvalue())
            self.assertEqual(payload["count"], 2)
            self.assertEqual(payload["records"][0]["memory_id"], "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa")
            self.assertEqual(payload["records"][1]["memory_id"], "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb")
            self.assertEqual(payload["records"][1]["retrieval_mode"], "graph_expand_v1")

    def test_cli_semantic_query_over_imported_payloads(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            state_file = str(pathlib.Path(tmpdir) / "state.json")
            run_cli(
                [
                    "--state-file",
                    state_file,
                    "--tenant-id",
                    "tenant-alpha",
                    "import-records",
                    "--records-json",
                    (
                        '[{"memory_id":"aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",'
                        '"payload":{"topic":"imported memory"},"source_id":"seed-1"}]'
                    ),
                    "--actor-json",
                    '{"id":"migration-bot","kind":"service"}',
                    "--default-timestamp",
                    "2026-03-22T00:00:00Z",
                ],
                stdout=io.StringIO(),
            )
            out_query = io.StringIO()
            run_cli(
                [
                    "--state-file",
                    state_file,
                    "--tenant-id",
                    "tenant-alpha",
                    "--capabilities-json",
                    '["override_retrieval_denials"]',
                    "query",
                    "--query-text",
                    "imported memory",
                ],
                stdout=out_query,
            )
            payload = json.loads(out_query.getvalue())
            self.assertEqual(payload["count"], 1)
            self.assertTrue(payload["records"][0]["queryable_payload_present"])
            self.assertEqual(payload["records"][0]["retrieval_mode"], "lexical_v1")

    def test_cli_peek_recall_and_reconsolidate(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            state_file = str(pathlib.Path(tmpdir) / "state.json")
            keyring_json = '{"dev-key":{"key":"super-secret","status":"active"}}'
            run_cli(
                [
                    "--state-file",
                    state_file,
                    "--tenant-id",
                    "tenant-alpha",
                    "--keyring-json",
                    keyring_json,
                    "ingest-event",
                    "--event-json",
                    self._signed_event_json(),
                ],
                stdout=io.StringIO(),
            )

            out_peek = io.StringIO()
            run_cli(
                [
                    "--state-file",
                    state_file,
                    "--tenant-id",
                    "tenant-alpha",
                    "--keyring-json",
                    keyring_json,
                    "peek",
                    "--memory-id",
                    "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
                ],
                stdout=out_peek,
            )
            peek_payload = json.loads(out_peek.getvalue())
            self.assertEqual(peek_payload["record"]["version"], 1)

            out_recall = io.StringIO()
            run_cli(
                [
                    "--state-file",
                    state_file,
                    "--tenant-id",
                    "tenant-alpha",
                    "--keyring-json",
                    keyring_json,
                    "recall",
                    "--memory-id",
                    "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
                    "--actor-json",
                    '{"id":"svc-memory","kind":"service"}',
                    "--event-id",
                    "22222222-2222-4222-8222-222222222222",
                    "--timestamp-json",
                    '{"wall_time":"2026-03-22T00:00:00Z","tick":5}',
                ],
                stdout=out_recall,
            )
            recall_payload = json.loads(out_recall.getvalue())
            self.assertEqual(recall_payload["outcome"], "appended")
            self.assertEqual(recall_payload["record"]["version"], 1)
            self.assertEqual(recall_payload["record"]["recall_count"], 1)

            out_recon = io.StringIO()
            run_cli(
                [
                    "--state-file",
                    state_file,
                    "--tenant-id",
                    "tenant-alpha",
                    "--keyring-json",
                    keyring_json,
                    "reconsolidate",
                    "--memory-id",
                    "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
                    "--actor-json",
                    '{"id":"svc-memory","kind":"service"}',
                    "--payload-hash",
                    "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                    "--event-id",
                    "33333333-3333-4333-8333-333333333333",
                    "--timestamp-json",
                    '{"wall_time":"2026-03-22T00:00:00Z","tick":6}',
                ],
                stdout=out_recon,
            )
            recon_payload = json.loads(out_recon.getvalue())
            self.assertEqual(recon_payload["outcome"], "appended")
            self.assertEqual(recon_payload["record"]["version"], 2)
            self.assertEqual(recon_payload["record"]["reconsolidation_count"], 1)

    def test_cli_assess_promotion_and_promote(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            state_file = str(pathlib.Path(tmpdir) / "state.json")
            keyring_json = '{"dev-key":{"key":"super-secret","status":"active"}}'
            run_cli(
                [
                    "--state-file",
                    state_file,
                    "--tenant-id",
                    "tenant-alpha",
                    "--keyring-json",
                    keyring_json,
                    "ingest-event",
                    "--event-json",
                    self._signed_event_json(payload={"topic": "episodic alpha"}),
                ],
                stdout=io.StringIO(),
            )

            out_assess = io.StringIO()
            run_cli(
                [
                    "--state-file",
                    state_file,
                    "--tenant-id",
                    "tenant-alpha",
                    "--keyring-json",
                    keyring_json,
                    "assess-promotion",
                    "--memory-id",
                    "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
                ],
                stdout=out_assess,
            )
            assess_payload = json.loads(out_assess.getvalue())
            self.assertTrue(assess_payload["promotion_eligible"])
            self.assertEqual(assess_payload["memory_class"], "episodic")

            out_promote = io.StringIO()
            run_cli(
                [
                    "--state-file",
                    state_file,
                    "--tenant-id",
                    "tenant-alpha",
                    "--keyring-json",
                    keyring_json,
                    "--capabilities-json",
                    '["override_retrieval_denials"]',
                    "promote",
                    "--memory-ids-json",
                    '["aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"]',
                    "--actor-json",
                    '{"id":"auditor","kind":"service"}',
                    "--payload-json",
                    '{"topic":"semantic alpha"}',
                    "--promoted-memory-id",
                    "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
                    "--event-id",
                    "22222222-2222-4222-8222-222222222222",
                    "--timestamp-json",
                    '{"wall_time":"2026-03-22T00:00:00Z","tick":2}',
                ],
                stdout=out_promote,
            )
            promote_payload = json.loads(out_promote.getvalue())
            self.assertEqual(promote_payload["outcome"], "appended")
            self.assertEqual(promote_payload["event"]["event_type"], "promoted")
            self.assertEqual(promote_payload["event"]["memory_class"], "semantic")

    def test_cli_promote_denies_untrusted_source(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            state_file = str(pathlib.Path(tmpdir) / "state.json")
            run_cli(
                [
                    "--state-file",
                    state_file,
                    "--tenant-id",
                    "tenant-alpha",
                    "import-records",
                    "--records-json",
                    '[{"memory_id":"aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa","payload":{"topic":"unsigned source"},"source_id":"seed-1"}]',
                    "--actor-json",
                    '{"id":"migration-bot","kind":"service"}',
                    "--default-timestamp",
                    "2026-03-22T00:00:00Z",
                ],
                stdout=io.StringIO(),
            )
            out_promote = io.StringIO()
            run_cli(
                [
                    "--state-file",
                    state_file,
                    "--tenant-id",
                    "tenant-alpha",
                    "promote",
                    "--memory-ids-json",
                    '["aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"]',
                    "--actor-json",
                    '{"id":"svc-memory","kind":"service"}',
                    "--payload-json",
                    '{"topic":"semantic denied"}',
                    "--promoted-memory-id",
                    "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
                    "--event-id",
                    "22222222-2222-4222-8222-222222222222",
                    "--timestamp-json",
                    '{"wall_time":"2026-03-22T00:00:00Z","tick":2}',
                ],
                stdout=out_promote,
            )
            promote_payload = json.loads(out_promote.getvalue())
            self.assertEqual(promote_payload["outcome"], "denied")
            self.assertIn(
                "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
                promote_payload["source_denials"],
            )

    def test_cli_ed25519_signed_ingest_with_jwk_keyring(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            state_file = str(pathlib.Path(tmpdir) / "state.json")
            event_json, keyring_json = self._ed25519_signed_event_json()
            run_cli(
                [
                    "--state-file",
                    state_file,
                    "--tenant-id",
                    "tenant-alpha",
                    "--keyring-json",
                    keyring_json,
                    "ingest-event",
                    "--event-json",
                    event_json,
                ],
                stdout=io.StringIO(),
            )
            out_query = io.StringIO()
            run_cli(
                [
                    "--state-file",
                    state_file,
                    "--tenant-id",
                    "tenant-alpha",
                    "--keyring-json",
                    keyring_json,
                    "query",
                ],
                stdout=out_query,
            )
            payload = json.loads(out_query.getvalue())
            self.assertEqual(payload["count"], 1)
            self.assertEqual(payload["records"][0]["signature_state"], "verified")
