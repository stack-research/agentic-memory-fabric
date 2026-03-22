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


class CliTests(unittest.TestCase):
    def test_cli_contracts_and_deterministic_json_output(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            state_file = str(pathlib.Path(tmpdir) / "state.json")

            out = io.StringIO()
            rc = run_cli(
                [
                    "--state-file",
                    state_file,
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
            run_cli(["--state-file", state_file, "query"], stdout=out_default)
            query_default = json.loads(out_default.getvalue())
            self.assertEqual(query_default["count"], 0)

            out_override = io.StringIO()
            run_cli(
                [
                    "--state-file",
                    state_file,
                    "query",
                    "--policy-json",
                    '{"capabilities":["override_retrieval_denials"]}',
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
                    "explain",
                    "--memory-id",
                    "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
                ],
                stdout=out_explain,
            )
            explain_payload = json.loads(out_explain.getvalue())
            self.assertEqual(explain_payload["trace"][0]["event_type"], "imported")

            out_prov_a = io.StringIO()
            run_cli(["--state-file", state_file, "export-provenance"], stdout=out_prov_a)
            out_prov_b = io.StringIO()
            run_cli(["--state-file", state_file, "export-provenance"], stdout=out_prov_b)
            self.assertEqual(out_prov_a.getvalue(), out_prov_b.getvalue())
