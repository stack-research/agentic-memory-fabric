# Milestones

This document records the major implementation milestones for **Agentic Memory Fabric** (control-plane MVP). Milestones are numbered in delivery order; later work builds on earlier layers.

| # | Milestone | Summary |
|---|-----------|---------|
| 1 | Control plane baseline | Repository layout (`src/`, `tests/`, `schemas/`, `docs/`), package skeleton, README mission and non-goals. |
| 2 | Event schema + replay core | JSON schema for event envelopes, `EventEnvelope` + validation, append-only log, deterministic `replay_events` → materialized `MemoryState`. |
| 3 | Trust-gated retrieval | `PolicyContext`, retrieval policy evaluation, hard denies for quarantined / expired / deleted (and related states) with override rules. |
| 4 | Explain + export | `explain()` lineage traces; SBOM snapshot vs provenance log exports; tenant-aware exports where applicable. |
| 5 | Decay / TTL policy | Logical-tick decay integration in policy; freshness vs historical truth. |
| 6 | Signed events + attestation | HMAC-SHA256 signing/verification, signature state on replay, attestation fields on envelopes. |
| 7 | Import / migration hardening | `imported` events, controlled import path, no silent trusted writes; signature verifier on import when configured. |
| 8 | Service surface | HTTP API (`ServiceApp`, `run_http_server`) and JSON-first CLI (`run_cli`) over `MemoryRuntime`. |
| 9 | SQLite persistence | `SQLiteEventLog`, durable append + replay, bootstrap from disk; invariants across restarts. |
| 10 | AuthN / AuthZ + multi-tenant | Trusted auth context, tenant scoping on requests, policy override only for trusted subjects; `tenant_id` on events and state. |
| 11 | Key management | `KeyMaterial` lifecycle (active/revoked), distinct signature outcomes (`key_missing`, `revoked`), keyring wiring in runtime/service/CLI. |
| 12 | Read-model optimization | Runtime state/event caches, SQLite single-pass reads and sequence-range helpers for fewer full scans. |
| 13 | Audit + telemetry | `AuditSink`, structured audit for query/get/explain; HTTP request audit wrapper; CLI `--audit-jsonl`. |
| 14 | Attestation policy gates | Opt-in policy: `require_attestation`, trust level, allowed issuers; materialized attestation fields in `MemoryState`; replay/tests. |
| 15 | Asymmetric signing (Ed25519 / JWKS) | `ed25519` algorithm in verification path, JWK-like key material in keyring, schema + service/CLI tests. |
| 16 | SQLite lineage indexing | Denormalized `memory_id` / `tenant_id` on events, index + migration; `events_for_memory` / range variants; scoped explain/provenance loads. |
| 17 | Export audit | Runtime audit events `memory.export.snapshot` and `memory.export.provenance` (counts, filters, `load_strategy`, denial path); docs + tests. |

## Backlog (not yet planned as numbered milestones)

Items below extend the shipped MVP thread (milestones 1–17 above). They are drawn from [`AGENTS.md`](../AGENTS.md) (product spec, §8–§12, roadmap) and explicit follow-ups deferred during delivery.

### Product / control plane

- **Vector or hybrid `query`** — semantic search over the materialized *sound* set; **policy-labeled embedding indexes** so shadow vectors cannot bypass retrieval gates (see open questions in `AGENTS.md`).
- **First-class lifecycle APIs** — named `quarantine` / `release` / `expire` operations on HTTP/CLI (beyond expressing them only via generic event ingest).
- **Pluggable merge / conflict resolution** — latest-wins, human-gate, source-rank, typed slots as a control-plane resolver module (not only “append another event”).

### Crypto / provenance

- **Content-addressed payloads** (CID-style) and **Merkle batch** / periodic notarization of event batches.
- **Remote JWKS** — fetch and cache signing keys by URL (OIDC-style); out of scope for the Ed25519/JWKS milestone that used static keyrings only.

### Platform / scale-out

- **Postgres (or similar) service backend** — partitioned event log, outbox, async index or materialized view updates (`AGENTS.md` §8 Phase 1).
- **Object / blob storage** for large attachments; events retain **payload hash** (and metadata), not giant rows.
- **Enterprise multi-tenant hardening** — row-level security, optional per-tenant KMS (`AGENTS.md` §8 Phase 2).

### Cross-cutting / integrations

- **Federation** — cross-agent or cross-trust-domain memory sharing under explicit policy boundaries (`AGENTS.md` §11).
- **Drift detectors** — surface conflicts with new external evidence as `quarantine` *suggestions* (no silent overwrite).
- **Additional SDKs** (e.g. Node) and **thin framework adapters** (LangGraph, AutoGen, Semantic Kernel, etc.) — call `ingest` / `query` / `explain` only.
- **OpenTelemetry** (or similar) — spans/metrics for ingest, query, policy denial, exports; complements JSONL `audit_sink`, not a replacement for product audit semantics.

### Follow-ups from recent milestones

- **Ingest transformation pipeline** — policy-gated redaction or enrichment on ingest (explicit policy; no silent mutation).
- **Export observability** — response size / streaming-oriented metrics in addition to structured export audit events.

## See also

- Direction and product spec: [`AGENTS.md`](../AGENTS.md)
- HTTP/CLI quickstart and audit hooks: [`README.md`](../README.md)
