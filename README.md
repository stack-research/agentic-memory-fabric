# Agentic Memory Fabric

Agentic Memory Fabric is a memory control plane for AI systems. It treats durable memory as governed infrastructure—enforced at the system layer rather than through ad hoc prompt engineering. Append-only events form lineage, policy gates retrieval, and exports distinguish current sound state from historical truth.

In this causal memory fabric, events shape memory spacetime; time and integrity shape reality.

## Mission

- Build governed memory infrastructure with append-only lineage.
- Enforce trust-state-aware retrieval by default.
- Provide explainable and auditable exports that separate:
  - memory SBOM snapshot (what is sound now under policy)
  - provenance log slice (what happened over time)

## Non-goals

- Not an LLM wrapper or orchestration framework replacement.
- Not snapshot theater that omits supersession, expiration, quarantine, or deletion history.
- Not silent trusted writes during import or migration.

## SQLite lineage indexing

When using a SQLite-backed store (`open_runtime(db_path=...)`), `memory_id` and `tenant_id` are stored as indexed columns on each row. **`explain`** and **`export_provenance`** with a `memory_id` filter load only matching events (ordered by sequence) instead of scanning the full log. Replay and `state_map` still read the complete append-only history.

## Immediate MVP Outcomes

- Stable event envelope and append-only log primitives.
- Replayable materialized view of current memory state.
- Retrieval contract with hard deny for `quarantined`, `expired`, and `deleted` by default.
- Explain API for ordered lineage traces.
- Export APIs for policy-scoped snapshot and provenance log slices.

## HTTP and CLI Quickstart

### HTTP (in-process server)

```python
from agentic_memory_fabric.service import run_http_server

server = run_http_server(
    host="127.0.0.1",
    port=8000,
    keyring={"dev-key": "super-secret"},
)
server.serve_forever()
```

Example endpoints:
- `POST /ingest/event`
- `POST /ingest/import`
- `POST /query`
- `GET /memory/{memory_id}/explain`
- `POST /export/snapshot`
- `POST /export/provenance`

### CLI (JSON-first)

```bash
python -m agentic_memory_fabric.cli --state-file .amf-state.json import-records \
  --tenant-id tenant-alpha \
  --records-json '[{"memory_id":"aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa","payload":{"v":"x"},"source_id":"seed-1"}]' \
  --actor-json '{"id":"migration-bot","kind":"service"}' \
  --default-timestamp "2026-03-22T00:00:00Z"

python -m agentic_memory_fabric.cli --state-file .amf-state.json query \
  --tenant-id tenant-alpha \
  --capabilities-json '["override_retrieval_denials"]' \
  --keyring-json '{"dev-key":{"key":"super-secret","status":"active"}}'
```

## Audit Hooks

Runtime operations can emit structured audit records through an optional sink callback.
Current event types include `memory.query`, `memory.get`, and `memory.explain`.

```python
from agentic_memory_fabric.runtime import open_runtime

audit_events = []
runtime = open_runtime(audit_sink=audit_events.append)

# run query/get/explain...
# audit_events now contains deterministic dictionaries, for example:
# {"type":"memory.query","tenant_id":"tenant-alpha","allowed":1,"denied_by_reason":{}}
```

CLI can write the same records as JSONL:

```bash
python -m agentic_memory_fabric.cli --state-file .amf-state.json \
  --tenant-id tenant-alpha \
  --audit-jsonl .amf-audit.jsonl \
  query
```

## Ed25519/JWKS Keyring Example

Asymmetric verification is supported with `signature.alg = "ed25519"` and JWK-like public keys:

```json
{
  "ed-key": {
    "kty": "OKP",
    "crv": "Ed25519",
    "x": "11qYAYLef2u4L6vR7M1gk9YbS1VZp6Qj4Lx1p9bQx8w"
  }
}
```

You can pass this through CLI `--keyring-json` or `open_runtime(keyring=...)`.

## Opt-In Attestation Gates

Attestation checks are opt-in through `policy_context`; default retrieval behavior is unchanged.

HTTP query example:

```json
{
  "policy_context": {
    "require_attestation": true,
    "min_attestation_trust_level": "medium",
    "allowed_attestation_issuers": ["issuer-alpha", "issuer-beta"]
  }
}
```

CLI query example:

```bash
python -m agentic_memory_fabric.cli --state-file .amf-state.json \
  --tenant-id tenant-alpha \
  query \
  --policy-json '{"require_attestation": true, "min_attestation_trust_level": "medium", "allowed_attestation_issuers": ["issuer-alpha"]}'
```
