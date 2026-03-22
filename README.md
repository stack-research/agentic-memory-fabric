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
