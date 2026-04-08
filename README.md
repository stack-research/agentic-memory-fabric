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
- `POST /link`
- `POST /reinforce`
- `POST /conflict`
- `POST /assess-conflict`
- `POST /memory/{memory_id}/peek`
- `POST /memory/{memory_id}/assess-promotion`
- `POST /memory/{memory_id}/recall`
- `POST /memory/{memory_id}/reconsolidate`
- `POST /promote`
- `POST /merge/propose`
- `POST /merge/approve`
- `POST /merge/reject`
- `GET /memory/{memory_id}/explain`
- `POST /export/snapshot`
- `POST /export/provenance`

### CLI (JSON-first)

```bash
python3 -m agentic_memory_fabric.cli --state-file .amf-state.json import-records \
  --tenant-id tenant-alpha \
  --records-json '[{"memory_id":"aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa","payload":{"v":"x"},"source_id":"seed-1"}]' \
  --actor-json '{"id":"migration-bot","kind":"service"}' \
  --default-timestamp "2026-03-22T00:00:00Z"

python3 -m agentic_memory_fabric.cli --state-file .amf-state.json query \
  --tenant-id tenant-alpha \
  --capabilities-json '["override_retrieval_denials"]' \
  --keyring-json '{"dev-key":{"key":"super-secret","status":"active"}}'

python3 -m agentic_memory_fabric.cli --state-file .amf-state.json query \
  --tenant-id tenant-alpha \
  --keyring-json '{"dev-key":{"key":"super-secret","status":"active"}}' \
  --policy-json '{"uncertainty_threshold": 0.8, "uncertainty_score": 0.4}'

python3 -m agentic_memory_fabric.cli --state-file .amf-state.json query \
  --tenant-id tenant-alpha \
  --keyring-json '{"dev-key":{"key":"super-secret","status":"active"}}' \
  --policy-json '{"uncertainty_threshold": 0.8, "uncertainty_score": 0.9}'

python3 -m agentic_memory_fabric.cli --state-file .amf-state.json query \
  --tenant-id tenant-alpha \
  --keyring-json '{"dev-key":{"key":"super-secret","status":"active"}}' \
  --query-text "memory fabric" \
  --structured-filter-json '{"queryable_payload_present": true}'

python3 -m agentic_memory_fabric.cli --state-file .amf-state.json link \
  --tenant-id tenant-alpha \
  --keyring-json '{"dev-key":{"key":"super-secret","status":"active"}}' \
  --source-memory-id aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa \
  --target-memory-id bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb \
  --actor-json '{"id":"svc-memory","kind":"service"}'

python3 -m agentic_memory_fabric.cli --state-file .amf-state.json query \
  --tenant-id tenant-alpha \
  --keyring-json '{"dev-key":{"key":"super-secret","status":"active"}}' \
  --query-text "memory fabric" \
  --graph-expand

python3 -m agentic_memory_fabric.cli --state-file .amf-state.json assess-conflict \
  --tenant-id tenant-alpha \
  --keyring-json '{"dev-key":{"key":"super-secret","status":"active"}}' \
  --memory-id aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa \
  --related-memory-id bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb

python3 -m agentic_memory_fabric.cli --state-file .amf-state.json merge-propose \
  --tenant-id tenant-alpha \
  --keyring-json '{"dev-key":{"key":"super-secret","status":"active"}}' \
  --memory-ids-json '["aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa","bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"]' \
  --actor-json '{"id":"reviewer","kind":"user"}' \
  --payload-json '{"topic":"merged memory fabric"}' \
  --resolver-kind human_gate

python3 -m agentic_memory_fabric.cli --state-file .amf-state.json recall \
  --tenant-id tenant-alpha \
  --memory-id aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa \
  --actor-json '{"id":"svc-memory","kind":"service"}'

python3 -m agentic_memory_fabric.cli --state-file .amf-state.json assess-promotion \
  --tenant-id tenant-alpha \
  --memory-id aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa

python3 -m agentic_memory_fabric.cli --state-file .amf-state.json promote \
  --tenant-id tenant-alpha \
  --capabilities-json '["override_retrieval_denials"]' \
  --memory-ids-json '["aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"]' \
  --actor-json '{"id":"auditor","kind":"service"}' \
  --payload-json '{"topic":"semantic memory fabric"}'
```

`query` stays backward-compatible. If `query_text` is omitted, AMF returns the inventory-style listing over the current sound set. If `query_text` is present, AMF searches only current heads whose governed inline payloads can materialize `retrieval_text`, then re-checks normal retrieval policy before returning each hit.

## Inline Payloads and Semantic-Ready Search

Events may now carry optional inline `payload` content alongside `payload_hash`. When payload is present, AMF verifies the canonical hash, materializes the payload in the read model, derives deterministic `retrieval_text`, and indexes only current queryable heads.

This milestone keeps the query baseline deterministic and in-process:

- retrieval mode is `lexical_v1`
- score is token overlap plus an exact-substring bonus
- stale index hits are discarded if `indexed_event_id` no longer matches the current head
- uncertainty gating still runs before any index lookup

Semantic query records include:

- `retrieval_score`
- `retrieval_mode`
- `indexed_event_id`
- `queryable_payload_present`

## Scored Memory Graph and Conflict-Aware Retrieval

AMF now supports governed one-hop graph edges between memories through append-only `linked`, `reinforced`, and `conflicted` events. These edges stay in lineage; they are not stored in a mutable side table.

Replay, retrieval, and snapshot records now include:

- `reinforcement_score`
- `conflict_score`
- `related_memory_ids`
- `conflicted_memory_ids`

When `query_text` is present, `query` combines lexical score with recency, reinforcement, and conflict penalty. Graph expansion is opt-in through `graph_expand`; when enabled, AMF returns direct matches first and then eligible one-hop neighbors, while still re-running normal retrieval policy on every expanded candidate.

Structured filters now also support:

- `min_reinforcement_score`
- `max_conflict_score`

## Governed Conflict Resolution

Conflict is now a first-class workflow, not just a ranking signal. AMF can assess whether conflicting memories are currently resolvable under policy, create quarantined merge proposals, and then explicitly approve or reject those proposals without rewriting source histories.

Merge proposal and resolution records extend the read model with:

- `conflict_open`
- `merged_into_memory_id`
- `superseded_by_memory_id`
- `resolved_from_memory_ids`

`merge_proposed` creates a semantic candidate memory that is quarantined by default. `merge_approved` flips that candidate to trusted and links each source memory to the merged result through `merged_into_memory_id` and `superseded_by_memory_id`. `merge_rejected` closes the proposal without superseding the sources.

## Explicit Memory Classes and Promotion

AMF now distinguishes `episodic` and `semantic` memories explicitly. Legacy memories replay as `episodic` by default. Promotion is an explicit control-plane operation that creates a new semantic memory with provenance links back to the source episodic memories; it does not mutate the source memory into a different class and it does not trigger model training.

Retrieval and snapshot records now include:

- `memory_class`
- `promotion_score`
- `promotion_eligible`
- `promoted_from_memory_ids`

Use `assess-promotion` to score and gate a source memory under current policy, and `promote` to append a new semantic candidate memory with caller-supplied payload.

### CLI walkthrough scripts

For end-to-end, human-readable examples (with sectioned output and pretty-printed JSON), see:

- `examples/README.md`
- `examples/real-world-cli-import-audit.sh`
- `examples/real-world-cli-signed-ingest.sh`
- `examples/real-world-cli-trusted-text.sh`
- `examples/real-world-cli-poisoning-attempt.sh`
- `examples/real-world-cli-decay-half-life.sh`

## Local Dev Vector Backend

The shipped runtime still uses the deterministic in-memory query index by default. For the next phase, the repo now includes [`docker-compose.pgvector.yml`](/Users/macos-user/.projects/stack-research/agentic-memory-fabric/docker-compose.pgvector.yml) as local-dev scaffolding for a Postgres + `pgvector` backend:

```bash
docker compose -f docker-compose.pgvector.yml up -d
```

That container is optional. Default tests and library flows do not require it.

## Audit Hooks

Runtime operations can emit structured audit records through an optional sink callback.
Current event types include:
- `memory.query`
- `memory.get`
- `memory.peek`
- `memory.link`
- `memory.reinforce`
- `memory.conflict`
- `memory.assess_conflict`
- `memory.assess_promotion`
- `memory.recall`
- `memory.reconsolidate`
- `memory.promote`
- `memory.merge_propose`
- `memory.merge_approve`
- `memory.merge_reject`
- `memory.explain`
- `memory.export.snapshot`
- `memory.export.provenance`

```python
from agentic_memory_fabric.runtime import open_runtime

audit_events = []
runtime = open_runtime(audit_sink=audit_events.append)

# run query/get/explain/export...
# audit_events now contains deterministic dictionaries, for example:
# {"type":"memory.query","tenant_id":"tenant-alpha","allowed":1,"denied_by_reason":{}}
```

CLI can write the same records as JSONL:

```bash
python3 -m agentic_memory_fabric.cli --state-file .amf-state.json \
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
python3 -m agentic_memory_fabric.cli --state-file .amf-state.json \
  --tenant-id tenant-alpha \
  query \
  --policy-json '{"require_attestation": true, "min_attestation_trust_level": "medium", "allowed_attestation_issuers": ["issuer-alpha"]}'
```
