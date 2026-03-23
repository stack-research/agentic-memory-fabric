"""Milestone 16: lineage index correctness (scoped reads vs full-scan oracle)."""

from __future__ import annotations

import json
import pathlib
import sqlite3
import sys
import tempfile
import unittest

PROJECT_ROOT = pathlib.Path(__file__).resolve().parents[1]
SRC_ROOT = PROJECT_ROOT / "src"
if str(SRC_ROOT) not in sys.path:
    sys.path.insert(0, str(SRC_ROOT))

from agentic_memory_fabric.events import EventEnvelope
from agentic_memory_fabric.explain import explain
from agentic_memory_fabric.export import export_provenance_log
from agentic_memory_fabric.log import AppendOnlyEventLog
from agentic_memory_fabric.runtime import open_runtime
from agentic_memory_fabric.sqlite_store import SQLiteEventLog


MEM_A = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
MEM_B = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
TENANT = "tenant-alpha"


def _event_dict(
    *,
    sequence: int,
    event_id: str,
    memory_id: str,
    event_type: str,
    previous_events: list[str],
    tenant_id: str = TENANT,
) -> dict:
    payload_char = format(sequence % 16, "x")
    payload_hash = "sha256:" + (payload_char * 64)
    return {
        "event_id": event_id,
        "sequence": sequence,
        "timestamp": {"wall_time": "2026-03-22T00:00:00Z", "tick": sequence},
        "actor": {"id": "svc-memory", "kind": "service"},
        "tenant_id": tenant_id,
        "memory_id": memory_id,
        "event_type": event_type,
        "previous_events": previous_events,
        "payload_hash": payload_hash,
    }


class LineageIndexTests(unittest.TestCase):
    def test_legacy_sqlite_migration_backfills_columns_and_creates_index(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = pathlib.Path(tmpdir) / "legacy.db"
            conn = sqlite3.connect(db_path)
            conn.execute(
                """
                CREATE TABLE events (
                    sequence INTEGER PRIMARY KEY,
                    event_id TEXT NOT NULL UNIQUE,
                    event_json TEXT NOT NULL,
                    signature_state TEXT NOT NULL
                )
                """
            )
            payload = _event_dict(
                sequence=1,
                event_id="11111111-1111-4111-8111-111111111111",
                memory_id=MEM_A,
                event_type="created",
                previous_events=[],
            )
            conn.execute(
                """
                INSERT INTO events (sequence, event_id, event_json, signature_state)
                VALUES (1, ?, ?, 'unsigned')
                """,
                (payload["event_id"], json.dumps(payload, sort_keys=True)),
            )
            conn.commit()
            conn.close()

            log = SQLiteEventLog(db_path)
            try:
                self.assertEqual(len(log), 1)
                row = sqlite3.connect(db_path).execute(
                    "SELECT memory_id, tenant_id FROM events WHERE sequence = 1"
                ).fetchone()
                self.assertIsNotNone(row)
                assert row is not None
                self.assertEqual(row[0], MEM_A)
                self.assertEqual(row[1], TENANT)
                idx = sqlite3.connect(db_path).execute(
                    """
                    SELECT name FROM sqlite_master
                    WHERE type='index' AND name='idx_events_tenant_memory_seq'
                    """
                ).fetchone()
                self.assertIsNotNone(idx)
            finally:
                log.close()

    def test_append_only_events_for_memory_matches_explain_oracle(self) -> None:
        log = AppendOnlyEventLog()
        e1 = EventEnvelope.from_dict(
            _event_dict(
                sequence=1,
                event_id="11111111-1111-4111-8111-111111111111",
                memory_id=MEM_A,
                event_type="created",
                previous_events=[],
            )
        )
        e2 = EventEnvelope.from_dict(
            _event_dict(
                sequence=2,
                event_id="22222222-2222-4222-8222-222222222222",
                memory_id=MEM_B,
                event_type="created",
                previous_events=[],
            )
        )
        e3 = EventEnvelope.from_dict(
            _event_dict(
                sequence=3,
                event_id="33333333-3333-4333-8333-333333333333",
                memory_id=MEM_A,
                event_type="updated",
                previous_events=[e1.event_id],
            )
        )
        for ev in (e1, e2, e3):
            log.append(ev)

        full = explain(MEM_A, log.all_events(), tenant_id=TENANT)
        scoped = explain(MEM_A, log.events_for_memory(MEM_A, TENANT), tenant_id=TENANT)
        self.assertEqual(scoped, full)

    def test_sqlite_events_for_memory_matches_explain_and_provenance_oracles(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = pathlib.Path(tmpdir) / "mix.db"
            rt = open_runtime(db_path=db_path)
            rt.ingest_event(
                _event_dict(
                    sequence=1,
                    event_id="11111111-1111-4111-8111-111111111111",
                    memory_id=MEM_A,
                    event_type="created",
                    previous_events=[],
                )
            )
            rt.ingest_event(
                _event_dict(
                    sequence=2,
                    event_id="22222222-2222-4222-8222-222222222222",
                    memory_id=MEM_B,
                    event_type="created",
                    previous_events=[],
                )
            )
            rt.ingest_event(
                _event_dict(
                    sequence=3,
                    event_id="33333333-3333-4333-8333-333333333333",
                    memory_id=MEM_A,
                    event_type="updated",
                    previous_events=["11111111-1111-4111-8111-111111111111"],
                )
            )
            rt.ingest_event(
                _event_dict(
                    sequence=4,
                    event_id="44444444-4444-4444-8444-444444444444",
                    memory_id=MEM_B,
                    event_type="updated",
                    previous_events=["22222222-2222-4222-8222-222222222222"],
                )
            )

            log = rt.log
            assert isinstance(log, SQLiteEventLog)

            full_events = log.all_events()
            self.assertEqual(
                explain(MEM_A, full_events, tenant_id=TENANT),
                explain(MEM_A, log.events_for_memory(MEM_A, TENANT), tenant_id=TENANT),
            )

            oracle_prov = export_provenance_log(
                full_events,
                memory_id=MEM_A,
                tenant_id=TENANT,
            )
            scoped_prov = export_provenance_log(
                log.events_for_memory(MEM_A, TENANT),
                memory_id=MEM_A,
                tenant_id=TENANT,
            )
            self.assertEqual(scoped_prov, oracle_prov)

            oracle_range = export_provenance_log(
                full_events,
                sequence_range=(2, 3),
                memory_id=MEM_A,
                tenant_id=TENANT,
            )
            scoped_range = export_provenance_log(
                log.events_for_memory_in_sequence_range(
                    MEM_A,
                    TENANT,
                    start=2,
                    end=3,
                ),
                sequence_range=(2, 3),
                memory_id=MEM_A,
                tenant_id=TENANT,
            )
            self.assertEqual(scoped_range, oracle_range)

    def test_runtime_explain_uses_scoped_path_sqlite(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = pathlib.Path(tmpdir) / "rt.db"
            rt = open_runtime(db_path=db_path)
            rt.ingest_event(
                _event_dict(
                    sequence=1,
                    event_id="11111111-1111-4111-8111-111111111111",
                    memory_id=MEM_A,
                    event_type="created",
                    previous_events=[],
                )
            )
            rt.ingest_event(
                _event_dict(
                    sequence=2,
                    event_id="22222222-2222-4222-8222-222222222222",
                    memory_id=MEM_B,
                    event_type="created",
                    previous_events=[],
                )
            )
            trace = rt.explain(
                MEM_A,
                trusted_context={"tenant_id": TENANT, "role": "auditor"},
            )
            self.assertEqual(len(trace), 1)
            self.assertEqual(trace[0]["event_id"], "11111111-1111-4111-8111-111111111111")
