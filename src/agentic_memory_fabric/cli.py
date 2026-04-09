"""JSON-first CLI for AMF runtime operations."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Mapping, TextIO

from .crypto import KEY_STATUS_ACTIVE, KeyMaterial
from .query_index import TextEmbedder
from .runtime import AuditSink, MemoryRuntime, open_runtime


def _decode_keyring(raw: str) -> dict[str, bytes | str | Mapping[str, Any] | KeyMaterial]:
    parsed = json.loads(raw)
    if not isinstance(parsed, dict):
        raise ValueError("--keyring-json must decode to a JSON object")
    keyring: dict[str, bytes | str | Mapping[str, Any] | KeyMaterial] = {}
    for key_id, value in parsed.items():
        if isinstance(value, (str, bytes)):
            keyring[str(key_id)] = value
            continue
        if isinstance(value, dict):
            if value.get("kty") == "OKP" and value.get("crv") == "Ed25519":
                status = str(value.get("status", KEY_STATUS_ACTIVE))
                keyring[str(key_id)] = KeyMaterial(
                    key={"kty": "OKP", "crv": "Ed25519", "x": value.get("x")},
                    status=status,
                )
                continue
            key = value.get("key")
            status = str(value.get("status", KEY_STATUS_ACTIVE))
            if isinstance(key, Mapping):
                if key.get("kty") != "OKP" or key.get("crv") != "Ed25519":
                    raise ValueError(
                        f"keyring entry {key_id!r} key object must be Ed25519 JWK-like"
                    )
                keyring[str(key_id)] = KeyMaterial(
                    key={"kty": "OKP", "crv": "Ed25519", "x": key.get("x")},
                    status=status,
                )
                continue
            if not isinstance(key, (str, bytes)):
                raise ValueError(
                    f"keyring entry {key_id!r} must include string/bytes key or Ed25519 key object"
                )
            keyring[str(key_id)] = KeyMaterial(key=key, status=status)
            continue
        raise ValueError(f"unsupported keyring entry format for {key_id!r}")
    return keyring


def _load_state(
    path: Path,
    *,
    keyring: dict[str, bytes | str | Mapping[str, Any] | KeyMaterial],
    audit_sink: AuditSink | None = None,
    event_backend: str | None = None,
    event_backend_dsn: str | None = None,
    event_backend_schema: str = "amf_core",
    bootstrap_event_backend: bool = False,
    query_backend: str = "inmemory",
    query_backend_dsn: str | None = None,
    query_backend_schema: str = "amf_query",
    bootstrap_query_backend: bool = False,
    embedder: TextEmbedder | None = None,
) -> MemoryRuntime:
    if event_backend not in {None, "memory"}:
        raise ValueError("_load_state only supports in-memory state files")
    runtime = MemoryRuntime(
        keyring=dict(keyring),
        query_backend_name=query_backend,
        query_backend_dsn=query_backend_dsn,
        query_backend_schema=query_backend_schema,
        bootstrap_query_backend=bootstrap_query_backend,
        embedder=embedder,
    )
    if not path.exists():
        runtime.audit_sink = audit_sink
        return runtime
    raw = json.loads(path.read_text(encoding="utf-8"))
    for event in raw.get("events", []):
        runtime.ingest_event(event)
    runtime.audit_sink = audit_sink
    return runtime


def _save_state(path: Path, runtime: MemoryRuntime) -> None:
    payload = {"events": [event.to_dict() for event in runtime.log.all_events()]}
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _load_json_arg(raw: str) -> Any:
    return json.loads(raw)


def _build_audit_sink(path: Path | None) -> AuditSink | None:
    if path is None:
        return None

    def _sink(event: Mapping[str, Any]) -> None:
        with path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(dict(event), sort_keys=True) + "\n")

    return _sink


def run_cli(argv: list[str] | None = None, *, stdout: TextIO | None = None) -> int:
    out = stdout or sys.stdout
    parser = argparse.ArgumentParser(prog="amf")
    parser.add_argument("--state-file", default=".amf-state.json")
    parser.add_argument("--db", default=None)
    parser.add_argument("--tenant-id", required=True)
    parser.add_argument("--role", default="runtime")
    parser.add_argument("--capabilities-json", default="[]")
    parser.add_argument("--allow-overrides", action="store_true")
    parser.add_argument("--keyring-json", default="{}")
    parser.add_argument("--audit-jsonl", default=None)
    parser.add_argument("--query-backend", default="inmemory")
    parser.add_argument("--query-backend-dsn", default=None)
    parser.add_argument("--query-backend-schema", default="amf_query")
    parser.add_argument("--bootstrap-query-backend", action="store_true")
    parser.add_argument("--event-backend", default=None)
    parser.add_argument("--event-backend-dsn", default=None)
    parser.add_argument("--event-backend-schema", default="amf_core")
    parser.add_argument("--bootstrap-event-backend", action="store_true")
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
    p_query.add_argument("--query-text", default=None)
    p_query.add_argument("--structured-filter-json", default=None)
    p_query.add_argument("--trust-states-json", default="null")
    p_query.add_argument("--limit", type=int, default=None)
    p_query.add_argument("--graph-expand", action="store_true")
    p_query.add_argument("--graph-edge-kinds-json", default=None)

    p_peek = sub.add_parser("peek")
    p_peek.add_argument("--memory-id", required=True)

    p_assess = sub.add_parser("assess-promotion")
    p_assess.add_argument("--memory-id", required=True)
    p_assess.add_argument("--policy-json", default="{}")

    p_assess_conflict = sub.add_parser("assess-conflict")
    p_assess_conflict.add_argument("--memory-id", required=True)
    p_assess_conflict.add_argument("--related-memory-id", required=True)
    p_assess_conflict.add_argument("--policy-json", default="{}")

    p_recall = sub.add_parser("recall")
    p_recall.add_argument("--memory-id", required=True)
    p_recall.add_argument("--actor-json", required=True)
    p_recall.add_argument("--event-id", default=None)
    p_recall.add_argument("--timestamp-json", default=None)
    p_recall.add_argument("--evidence-refs-json", default=None)

    p_reconsolidate = sub.add_parser("reconsolidate")
    p_reconsolidate.add_argument("--memory-id", required=True)
    p_reconsolidate.add_argument("--actor-json", required=True)
    p_reconsolidate.add_argument("--payload-hash", required=True)
    p_reconsolidate.add_argument("--event-id", default=None)
    p_reconsolidate.add_argument("--timestamp-json", default=None)
    p_reconsolidate.add_argument("--evidence-refs-json", default=None)
    p_reconsolidate.add_argument("--payload-json", default=None)
    p_reconsolidate.add_argument("--signature-json", default=None)
    p_reconsolidate.add_argument("--attestation-json", default=None)

    p_link = sub.add_parser("link")
    p_link.add_argument("--source-memory-id", required=True)
    p_link.add_argument("--target-memory-id", required=True)
    p_link.add_argument("--actor-json", required=True)
    p_link.add_argument("--event-id", default=None)
    p_link.add_argument("--timestamp-json", default=None)
    p_link.add_argument("--evidence-refs-json", default=None)
    p_link.add_argument("--edge-weight", type=float, default=None)
    p_link.add_argument("--edge-reason", default=None)

    p_reinforce = sub.add_parser("reinforce")
    p_reinforce.add_argument("--memory-id", required=True)
    p_reinforce.add_argument("--related-memory-id", default=None)
    p_reinforce.add_argument("--actor-json", required=True)
    p_reinforce.add_argument("--event-id", default=None)
    p_reinforce.add_argument("--timestamp-json", default=None)
    p_reinforce.add_argument("--evidence-refs-json", default=None)
    p_reinforce.add_argument("--edge-weight", type=float, default=None)
    p_reinforce.add_argument("--edge-reason", default=None)

    p_conflict = sub.add_parser("conflict")
    p_conflict.add_argument("--source-memory-id", required=True)
    p_conflict.add_argument("--target-memory-id", required=True)
    p_conflict.add_argument("--actor-json", required=True)
    p_conflict.add_argument("--event-id", default=None)
    p_conflict.add_argument("--timestamp-json", default=None)
    p_conflict.add_argument("--evidence-refs-json", default=None)
    p_conflict.add_argument("--edge-weight", type=float, default=None)
    p_conflict.add_argument("--edge-reason", default=None)

    p_promote = sub.add_parser("promote")
    p_promote.add_argument("--memory-ids-json", required=True)
    p_promote.add_argument("--actor-json", required=True)
    p_promote.add_argument("--payload-json", required=True)
    p_promote.add_argument("--policy-json", default="{}")
    p_promote.add_argument("--promoted-memory-id", default=None)
    p_promote.add_argument("--event-id", default=None)
    p_promote.add_argument("--timestamp-json", default=None)
    p_promote.add_argument("--evidence-refs-json", default=None)

    p_merge_propose = sub.add_parser("merge-propose")
    p_merge_propose.add_argument("--memory-ids-json", required=True)
    p_merge_propose.add_argument("--actor-json", required=True)
    p_merge_propose.add_argument("--payload-json", required=True)
    p_merge_propose.add_argument("--resolver-kind", default="human_gate")
    p_merge_propose.add_argument("--resolution-reason", default=None)
    p_merge_propose.add_argument("--policy-json", default="{}")
    p_merge_propose.add_argument("--merged-memory-id", default=None)
    p_merge_propose.add_argument("--event-id", default=None)
    p_merge_propose.add_argument("--timestamp-json", default=None)
    p_merge_propose.add_argument("--evidence-refs-json", default=None)

    p_merge_approve = sub.add_parser("merge-approve")
    p_merge_approve.add_argument("--memory-id", required=True)
    p_merge_approve.add_argument("--actor-json", required=True)
    p_merge_approve.add_argument("--policy-json", default="{}")
    p_merge_approve.add_argument("--event-id", default=None)
    p_merge_approve.add_argument("--timestamp-json", default=None)
    p_merge_approve.add_argument("--evidence-refs-json", default=None)
    p_merge_approve.add_argument("--resolution-reason", default=None)

    p_merge_reject = sub.add_parser("merge-reject")
    p_merge_reject.add_argument("--memory-id", required=True)
    p_merge_reject.add_argument("--actor-json", required=True)
    p_merge_reject.add_argument("--policy-json", default="{}")
    p_merge_reject.add_argument("--event-id", default=None)
    p_merge_reject.add_argument("--timestamp-json", default=None)
    p_merge_reject.add_argument("--evidence-refs-json", default=None)
    p_merge_reject.add_argument("--resolution-reason", default=None)

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
    keyring = _decode_keyring(args.keyring_json)
    audit_sink = _build_audit_sink(Path(args.audit_jsonl) if args.audit_jsonl else None)
    if args.event_backend == "memory" and args.db:
        raise ValueError("--db cannot be combined with --event-backend memory")
    if args.event_backend == "sqlite" and not args.db:
        raise ValueError("--db is required when --event-backend sqlite is used")
    if args.event_backend == "postgres":
        runtime = open_runtime(
            event_backend="postgres",
            event_backend_dsn=args.event_backend_dsn,
            event_backend_schema=args.event_backend_schema,
            bootstrap_event_backend=args.bootstrap_event_backend,
            keyring=keyring,
            audit_sink=audit_sink,
            query_backend=args.query_backend,
            query_backend_dsn=args.query_backend_dsn,
            query_backend_schema=args.query_backend_schema,
            bootstrap_query_backend=args.bootstrap_query_backend,
        )
        state_path = None
    elif args.db:
        runtime = open_runtime(
            db_path=args.db,
            event_backend="sqlite",
            keyring=keyring,
            audit_sink=audit_sink,
            query_backend=args.query_backend,
            query_backend_dsn=args.query_backend_dsn,
            query_backend_schema=args.query_backend_schema,
            bootstrap_query_backend=args.bootstrap_query_backend,
        )
        state_path = None
    else:
        state_path = Path(args.state_file)
        runtime = _load_state(
            state_path,
            keyring=keyring,
            audit_sink=audit_sink,
            event_backend=args.event_backend,
            event_backend_dsn=args.event_backend_dsn,
            event_backend_schema=args.event_backend_schema,
            bootstrap_event_backend=args.bootstrap_event_backend,
            query_backend=args.query_backend,
            query_backend_dsn=args.query_backend_dsn,
            query_backend_schema=args.query_backend_schema,
            bootstrap_query_backend=args.bootstrap_query_backend,
        )
    capabilities = _load_json_arg(args.capabilities_json)
    if not isinstance(capabilities, list):
        raise ValueError("--capabilities-json must decode to a JSON array")
    trusted_context = {
        "tenant_id": args.tenant_id,
        "role": args.role,
        "capabilities": capabilities,
        "allow_overrides": args.allow_overrides,
    }

    try:
        if args.command == "ingest-event":
            event = runtime.ingest_event(
                _load_json_arg(args.event_json),
                expected_tenant_id=args.tenant_id,
                trusted_context=trusted_context,
            )
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
                tenant_id=args.tenant_id,
                expected_tenant_id=args.tenant_id,
                trusted_context=trusted_context,
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
            policy_context = _load_json_arg(args.policy_json)
            if not isinstance(policy_context, dict):
                raise ValueError("--policy-json must decode to a JSON object")
            policy_context["tenant_id"] = args.tenant_id
            result = runtime.query(
                policy_context=policy_context,
                trusted_context=trusted_context,
                query_text=args.query_text,
                structured_filter=(
                    _load_json_arg(args.structured_filter_json)
                    if args.structured_filter_json is not None
                    else None
                ),
                trust_states=set(trust_states_raw) if trust_states_raw is not None else None,
                limit=args.limit,
                graph_expand=args.graph_expand,
                graph_edge_kinds=(
                    _load_json_arg(args.graph_edge_kinds_json)
                    if args.graph_edge_kinds_json is not None
                    else None
                ),
            )
            out.write(json.dumps(result, sort_keys=True) + "\n")
            return 0

        if args.command == "peek":
            record = runtime.peek(
                args.memory_id,
                policy_context={"tenant_id": args.tenant_id},
                trusted_context=trusted_context,
            )
            out.write(
                json.dumps({"memory_id": args.memory_id, "record": record}, sort_keys=True) + "\n"
            )
            return 0

        if args.command == "assess-promotion":
            policy_context = _load_json_arg(args.policy_json)
            if not isinstance(policy_context, dict):
                raise ValueError("--policy-json must decode to a JSON object")
            policy_context["tenant_id"] = args.tenant_id
            assessment = runtime.assess_promotion(
                args.memory_id,
                policy_context=policy_context,
                trusted_context=trusted_context,
            )
            out.write(json.dumps(assessment, sort_keys=True) + "\n")
            return 0

        if args.command == "assess-conflict":
            policy_context = _load_json_arg(args.policy_json)
            if not isinstance(policy_context, dict):
                raise ValueError("--policy-json must decode to a JSON object")
            policy_context["tenant_id"] = args.tenant_id
            assessment = runtime.assess_conflict(
                args.memory_id,
                args.related_memory_id,
                policy_context=policy_context,
                trusted_context=trusted_context,
            )
            out.write(json.dumps(assessment, sort_keys=True) + "\n")
            return 0

        if args.command == "recall":
            result = runtime.recall(
                args.memory_id,
                actor=_load_json_arg(args.actor_json),
                policy_context={"tenant_id": args.tenant_id},
                trusted_context=trusted_context,
                event_id=args.event_id,
                timestamp=(
                    _load_json_arg(args.timestamp_json) if args.timestamp_json is not None else None
                ),
                evidence_refs=(
                    _load_json_arg(args.evidence_refs_json)
                    if args.evidence_refs_json is not None
                    else None
                ),
            )
            if state_path is not None and result["outcome"] == "appended":
                _save_state(state_path, runtime)
            out.write(json.dumps({"memory_id": args.memory_id, **result}, sort_keys=True) + "\n")
            return 0

        if args.command == "reconsolidate":
            result = runtime.reconsolidate(
                args.memory_id,
                actor=_load_json_arg(args.actor_json),
                payload_hash=args.payload_hash,
                payload=(
                    _load_json_arg(args.payload_json) if args.payload_json is not None else None
                ),
                policy_context={"tenant_id": args.tenant_id},
                trusted_context=trusted_context,
                event_id=args.event_id,
                timestamp=(
                    _load_json_arg(args.timestamp_json) if args.timestamp_json is not None else None
                ),
                evidence_refs=(
                    _load_json_arg(args.evidence_refs_json)
                    if args.evidence_refs_json is not None
                    else None
                ),
                signature=(
                    _load_json_arg(args.signature_json) if args.signature_json is not None else None
                ),
                attestation=(
                    _load_json_arg(args.attestation_json)
                    if args.attestation_json is not None
                    else None
                ),
            )
            if state_path is not None and result["outcome"] == "appended":
                _save_state(state_path, runtime)
            out.write(json.dumps({"memory_id": args.memory_id, **result}, sort_keys=True) + "\n")
            return 0

        if args.command == "link":
            result = runtime.link(
                args.source_memory_id,
                args.target_memory_id,
                actor=_load_json_arg(args.actor_json),
                policy_context={"tenant_id": args.tenant_id},
                trusted_context=trusted_context,
                event_id=args.event_id,
                timestamp=(
                    _load_json_arg(args.timestamp_json) if args.timestamp_json is not None else None
                ),
                evidence_refs=(
                    _load_json_arg(args.evidence_refs_json)
                    if args.evidence_refs_json is not None
                    else None
                ),
                edge_weight=args.edge_weight,
                edge_reason=args.edge_reason,
            )
            if state_path is not None and result["outcome"] == "appended":
                _save_state(state_path, runtime)
            out.write(json.dumps(result, sort_keys=True) + "\n")
            return 0

        if args.command == "reinforce":
            result = runtime.reinforce(
                args.memory_id,
                actor=_load_json_arg(args.actor_json),
                related_memory_id=args.related_memory_id,
                policy_context={"tenant_id": args.tenant_id},
                trusted_context=trusted_context,
                event_id=args.event_id,
                timestamp=(
                    _load_json_arg(args.timestamp_json) if args.timestamp_json is not None else None
                ),
                evidence_refs=(
                    _load_json_arg(args.evidence_refs_json)
                    if args.evidence_refs_json is not None
                    else None
                ),
                edge_weight=args.edge_weight,
                edge_reason=args.edge_reason,
            )
            if state_path is not None and result["outcome"] == "appended":
                _save_state(state_path, runtime)
            out.write(json.dumps(result, sort_keys=True) + "\n")
            return 0

        if args.command == "conflict":
            result = runtime.conflict(
                args.source_memory_id,
                args.target_memory_id,
                actor=_load_json_arg(args.actor_json),
                policy_context={"tenant_id": args.tenant_id},
                trusted_context=trusted_context,
                event_id=args.event_id,
                timestamp=(
                    _load_json_arg(args.timestamp_json) if args.timestamp_json is not None else None
                ),
                evidence_refs=(
                    _load_json_arg(args.evidence_refs_json)
                    if args.evidence_refs_json is not None
                    else None
                ),
                edge_weight=args.edge_weight,
                edge_reason=args.edge_reason,
            )
            if state_path is not None and result["outcome"] == "appended":
                _save_state(state_path, runtime)
            out.write(json.dumps(result, sort_keys=True) + "\n")
            return 0

        if args.command == "promote":
            policy_context = _load_json_arg(args.policy_json)
            if not isinstance(policy_context, dict):
                raise ValueError("--policy-json must decode to a JSON object")
            policy_context["tenant_id"] = args.tenant_id
            result = runtime.promote(
                _load_json_arg(args.memory_ids_json),
                actor=_load_json_arg(args.actor_json),
                payload=_load_json_arg(args.payload_json),
                policy_context=policy_context,
                trusted_context=trusted_context,
                promoted_memory_id=args.promoted_memory_id,
                event_id=args.event_id,
                timestamp=(
                    _load_json_arg(args.timestamp_json) if args.timestamp_json is not None else None
                ),
                evidence_refs=(
                    _load_json_arg(args.evidence_refs_json)
                    if args.evidence_refs_json is not None
                    else None
                ),
            )
            if state_path is not None and result["outcome"] == "appended":
                _save_state(state_path, runtime)
            out.write(json.dumps(result, sort_keys=True) + "\n")
            return 0

        if args.command == "merge-propose":
            policy_context = _load_json_arg(args.policy_json)
            if not isinstance(policy_context, dict):
                raise ValueError("--policy-json must decode to a JSON object")
            policy_context["tenant_id"] = args.tenant_id
            result = runtime.propose_merge(
                _load_json_arg(args.memory_ids_json),
                actor=_load_json_arg(args.actor_json),
                payload=_load_json_arg(args.payload_json),
                resolver_kind=args.resolver_kind,
                resolution_reason=args.resolution_reason,
                policy_context=policy_context,
                trusted_context=trusted_context,
                merged_memory_id=args.merged_memory_id,
                event_id=args.event_id,
                timestamp=(
                    _load_json_arg(args.timestamp_json) if args.timestamp_json is not None else None
                ),
                evidence_refs=(
                    _load_json_arg(args.evidence_refs_json)
                    if args.evidence_refs_json is not None
                    else None
                ),
            )
            if state_path is not None and result["outcome"] == "appended":
                _save_state(state_path, runtime)
            out.write(json.dumps(result, sort_keys=True) + "\n")
            return 0

        if args.command == "merge-approve":
            policy_context = _load_json_arg(args.policy_json)
            if not isinstance(policy_context, dict):
                raise ValueError("--policy-json must decode to a JSON object")
            policy_context["tenant_id"] = args.tenant_id
            result = runtime.approve_merge(
                args.memory_id,
                actor=_load_json_arg(args.actor_json),
                policy_context=policy_context,
                trusted_context=trusted_context,
                event_id=args.event_id,
                timestamp=(
                    _load_json_arg(args.timestamp_json) if args.timestamp_json is not None else None
                ),
                evidence_refs=(
                    _load_json_arg(args.evidence_refs_json)
                    if args.evidence_refs_json is not None
                    else None
                ),
                resolution_reason=args.resolution_reason,
            )
            if state_path is not None and result["outcome"] == "appended":
                _save_state(state_path, runtime)
            out.write(json.dumps(result, sort_keys=True) + "\n")
            return 0

        if args.command == "merge-reject":
            policy_context = _load_json_arg(args.policy_json)
            if not isinstance(policy_context, dict):
                raise ValueError("--policy-json must decode to a JSON object")
            policy_context["tenant_id"] = args.tenant_id
            result = runtime.reject_merge(
                args.memory_id,
                actor=_load_json_arg(args.actor_json),
                policy_context=policy_context,
                trusted_context=trusted_context,
                event_id=args.event_id,
                timestamp=(
                    _load_json_arg(args.timestamp_json) if args.timestamp_json is not None else None
                ),
                evidence_refs=(
                    _load_json_arg(args.evidence_refs_json)
                    if args.evidence_refs_json is not None
                    else None
                ),
                resolution_reason=args.resolution_reason,
            )
            if state_path is not None and result["outcome"] == "appended":
                _save_state(state_path, runtime)
            out.write(json.dumps(result, sort_keys=True) + "\n")
            return 0

        if args.command == "explain":
            trace = runtime.explain(
                args.memory_id,
                policy_context={"tenant_id": args.tenant_id},
                trusted_context=trusted_context,
            )
            out.write(json.dumps({"memory_id": args.memory_id, "trace": trace}, sort_keys=True) + "\n")
            return 0

        if args.command == "export-snapshot":
            policy_context = _load_json_arg(args.policy_json)
            if not isinstance(policy_context, dict):
                raise ValueError("--policy-json must decode to a JSON object")
            policy_context["tenant_id"] = args.tenant_id
            snapshot = runtime.export_snapshot(
                policy_context=policy_context,
                trusted_context=trusted_context,
            )
            out.write(json.dumps(snapshot, sort_keys=True) + "\n")
            return 0

        if args.command == "export-provenance":
            sequence_range = None
            if args.range_start is not None or args.range_end is not None:
                if args.range_start is None or args.range_end is None:
                    raise ValueError("both --range-start and --range-end are required together")
                sequence_range = (args.range_start, args.range_end)
            provenance = runtime.export_provenance(
                policy_context={"tenant_id": args.tenant_id},
                trusted_context=trusted_context,
                memory_id=args.memory_id,
                sequence_range=sequence_range,
            )
            out.write(json.dumps(provenance, sort_keys=True) + "\n")
            return 0

        raise ValueError(f"unknown command: {args.command}")
    finally:
        try:
            runtime.close()
        except Exception:
            pass


def main() -> int:
    return run_cli()


if __name__ == "__main__":
    raise SystemExit(main())
