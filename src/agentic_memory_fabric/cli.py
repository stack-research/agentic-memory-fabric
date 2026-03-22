"""JSON-first CLI for AMF runtime operations."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, TextIO

from .runtime import MemoryRuntime, open_runtime


def _load_state(path: Path) -> MemoryRuntime:
    runtime = MemoryRuntime()
    if not path.exists():
        return runtime
    raw = json.loads(path.read_text(encoding="utf-8"))
    for event in raw.get("events", []):
        runtime.ingest_event(event)
    return runtime


def _save_state(path: Path, runtime: MemoryRuntime) -> None:
    payload = {"events": [event.to_dict() for event in runtime.log.all_events()]}
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _load_json_arg(raw: str) -> Any:
    return json.loads(raw)


def run_cli(argv: list[str] | None = None, *, stdout: TextIO | None = None) -> int:
    out = stdout or sys.stdout
    parser = argparse.ArgumentParser(prog="amf")
    parser.add_argument("--state-file", default=".amf-state.json")
    parser.add_argument("--db", default=None)
    sub = parser.add_subparsers(dest="command", required=True)

    p_ingest = sub.add_parser("ingest-event")
    p_ingest.add_argument("--event-json", required=True)

    p_import = sub.add_parser("import-records")
    p_import.add_argument("--records-json", required=True)
    p_import.add_argument("--actor-json", required=True)
    p_import.add_argument("--default-timestamp", required=True)
    p_import.add_argument("--start-sequence", type=int, default=None)

    p_query = sub.add_parser("query")
    p_query.add_argument("--policy-json", default="{}")
    p_query.add_argument("--trust-states-json", default="null")
    p_query.add_argument("--limit", type=int, default=None)

    p_explain = sub.add_parser("explain")
    p_explain.add_argument("--memory-id", required=True)

    p_snapshot = sub.add_parser("export-snapshot")
    p_snapshot.add_argument("--policy-json", default="{}")

    p_prov = sub.add_parser("export-provenance")
    p_prov.add_argument("--memory-id", default=None)
    p_prov.add_argument("--range-start", type=int, default=None)
    p_prov.add_argument("--range-end", type=int, default=None)

    args = parser.parse_args(argv)
    runtime: MemoryRuntime
    state_path: Path | None
    if args.db:
        runtime = open_runtime(db_path=args.db)
        state_path = None
    else:
        state_path = Path(args.state_file)
        runtime = _load_state(state_path)

    if args.command == "ingest-event":
        event = runtime.ingest_event(_load_json_arg(args.event_json))
        if state_path is not None:
            _save_state(state_path, runtime)
        out.write(json.dumps({"event": event.to_dict()}, sort_keys=True) + "\n")
        return 0

    if args.command == "import-records":
        events = runtime.import_records(
            _load_json_arg(args.records_json),
            actor=_load_json_arg(args.actor_json),
            default_timestamp=args.default_timestamp,
            start_sequence=args.start_sequence,
        )
        if state_path is not None:
            _save_state(state_path, runtime)
        out.write(
            json.dumps(
                {"count": len(events), "events": [event.to_dict() for event in events]},
                sort_keys=True,
            )
            + "\n"
        )
        return 0

    if args.command == "query":
        trust_states_raw = _load_json_arg(args.trust_states_json)
        records = runtime.query(
            policy_context=_load_json_arg(args.policy_json),
            trust_states=set(trust_states_raw) if trust_states_raw is not None else None,
            limit=args.limit,
        )
        out.write(json.dumps({"count": len(records), "records": records}, sort_keys=True) + "\n")
        return 0

    if args.command == "explain":
        trace = runtime.explain(args.memory_id)
        out.write(json.dumps({"memory_id": args.memory_id, "trace": trace}, sort_keys=True) + "\n")
        return 0

    if args.command == "export-snapshot":
        snapshot = runtime.export_snapshot(policy_context=_load_json_arg(args.policy_json))
        out.write(json.dumps(snapshot, sort_keys=True) + "\n")
        return 0

    if args.command == "export-provenance":
        sequence_range = None
        if args.range_start is not None or args.range_end is not None:
            if args.range_start is None or args.range_end is None:
                raise ValueError("both --range-start and --range-end are required together")
            sequence_range = (args.range_start, args.range_end)
        provenance = runtime.export_provenance(
            memory_id=args.memory_id,
            sequence_range=sequence_range,
        )
        out.write(json.dumps(provenance, sort_keys=True) + "\n")
        return 0

    raise ValueError(f"unknown command: {args.command}")


def main() -> int:
    return run_cli()


if __name__ == "__main__":
    raise SystemExit(main())
