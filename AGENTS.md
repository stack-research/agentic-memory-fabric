# Agentic Memory Fabric

Project details, direction and resources to learn from:

- The project name was chosen as `agentic-memory-fabric`.
- The team explicitly likes the "fabric" metaphor and wants to lean into a spacetime/causality narrative.
- The product direction is to turn prior labs/POCs into one governed memory infrastructure system.
- Source projects to learn from:
  - `../../entropy-os/`
  - `../../memory-half-life/`
  - `../../memory-poisoning-supply-chain/`
- OWASP threat model detailing memory poisoning in [OWASP ASI06: Memory & Context Poisoning](./OWASP-Top-10-for-Agentic-Applications-2026-12.6-1.txt)

## Product intent (compressed)

Build infrastructure (not prompt tricks) for governed agent memory:

- append-only events + lineage
- decay/TTL policy modules
- trust-state-aware retrieval gates
- explainability/audit exports
- honest SBOM snapshot vs provenance-log semantics

## Priority outcomes for next session

1. Scaffold repository structure for a memory control plane MVP.
2. Port and harden primitives from source projects (see `AGENT_CONFLUENCE_MAP.md`).
3. Define stable event schema + retrieval contract + export formats.
4. Add replayable tests proving policy enforcement and lineage integrity.

----------------------------------------

# Agentic Memory Fabric - Confluence Map

This project should be the convergence of three prior efforts. The goal is not to copy repos wholesale, but to inherit strong primitives and upgrade them for product-grade governance.

## 1) Inherit from `../../memory-poisoning-supply-chain`

### High-value artifacts

- `artifacts/schemas/memory-sbom.v0.json`
  - Reuse as a starting point for snapshot schema semantics.
  - Keep trust states and source-channel enum lineage.
- `src/lab/store.py`
  - Reuse event-first mindset (stored, superseded, deleted, recalled).
  - Keep "synthetic_context injection surface" as a test instrument.
- `src/lab/sbom.py`
  - Reuse theater-vs-audit distinction.
  - Keep `sbom_gap_score` concept for regression tests.
- `src/lab/runner.py`
  - Reuse scenario-driven deterministic replay pattern.
- `LAB_SPEC.md` and `docs/lab-guide.md`
  - Mine threat model, scenario design, and anti-theater framing.

### What to adapt for product

- Replace UUID-only event IDs with stable sequence + optional signatures.
- Separate runtime internals from export APIs (no direct internal map access in prod code).
- Convert lab-specific scenario semantics into formal acceptance tests.

## 2) Inherit from `../../entropy-os`

### High-value artifacts

- `src/entropyos/store.py`
  - Deterministic TTL store with enforced expiry on read.
- `src/entropyos/runtime.py`
  - Clean core/shell separation and replayable logical clock.
- `src/entropyos/identity.py`
  - Canonical identity and alias validation contract (anti-confusion baseline).
- `src/entropyos/serde.py`
  - Canonical JSON serializer for stable hashes and reproducible artifacts.
- `docs/architecture.md`, `docs/entropy_model.md`
  - Architecture principles: deterministic core, explicit ticks, no hidden time.

### What to adapt for product

- Extend identity kinds for memory/event/evidence namespaces.
- Keep deterministic tick support for testing, but allow wall-clock metadata in production envelopes.
- Preserve canonical serialization in exports and provenance slices.

## 3) Inherit from `../../memory-half-life`

### High-value artifacts

- `src/memoryhalflife/memory.py`
  - `ttl_from_half_life` and confidence decay math.
- `src/memoryhalflife/engine.py`
  - Recall-refresh vs peek-no-refresh semantics.
- `tests/test_engine.py`, `tests/test_memory.py`
  - Directly portable behavior tests for decay and reinforcement.

### What to adapt for product

- Model decay as policy module, not deletion of history.
- On expiry, emit append-only `expired` events and hide from sound retrieval set.
- Keep confidence for ranking; never let it erase provenance-log truth.

## 4) Proposed "inherit vs build" boundary

- Inherit:
  - deterministic clock/tick mechanics
  - canonical IDs and serializer patterns
  - trust states and source-channel taxonomy
  - scenario-based replay tests
- Build new:
  - control-plane API surface (`ingest`, `query`, `explain`, exports)
  - policy engine with hard retrieval filters
  - attestation/evidence envelope model
  - provenance-log export and audit UX

## 5) Anti-patterns to avoid (learned from lab framing)

- Snapshot-only "SBOM theater" without lineage completeness.
- Labels that are not enforced in retrieval path.
- Silent trusted writes from migration/import.
- Key normalization ambiguities without explicit conflict policy.

## 6) First technical merge order

1. Event envelope + append-only log primitives.
2. Materialized sound-memory view with trust gates (sound-memory: not corrupted, not compromised, not fading, not deleted, or expired. basically integrity + freshness)
3. Explain/export APIs (snapshot + provenance).
4. Decay module integration as a policy. NOT optional.
5. Signed events and stronger attestations.

------------------

## Day 0 bootstrap

- Create initial repository layout:
  - `src/agentic_memory_fabric/`
  - `tests/`
  - `schemas/`
  - `docs/`
- Add a minimal README with mission and non-goals.

## MVP implementation order

1. Event model:
   - `event_id`, sequence, actor, previous_events, payload hash, evidence refs, trust transition.
2. Append-only storage + replay:
   - deterministic replay-from-zero tests.
3. Materialized current view:
   - stable `memory_id`, current trust state, version pointers.
4. Retrieval contract:
   - policy context required, hard deny for `quarantined`/`expired` by default.
5. Explain API:
   - ordered lineage trace for a memory.
6. Export API:
   - snapshot (sound now under policy)
   - provenance log slice (history over interval)

## Required tests before claiming MVP

- Quarantined/expired entries are excluded unless explicit override capability.
- SBOM snapshot equals materialized sound set.
- provenance log retains supersession, quarantine, expiration, and deleted.
- Import path emits `imported` events (no silent trusted writes).
- Deterministic replay yields identical state and exports.

## Suggested first code imports (conceptual, not direct copy)

- From `entropy-os`:
  - tick/time discipline, canonical serialization, identity normalization.
- From `memory-half-life`:
  - half-life math and recall/peek semantics as optional policy module.
- From `memory-poisoning-supply-chain`:
  - SBOM schema shape, gap-score style tests, scenario runner pattern.

## Naming direction

Working name and narrative:

- project: `agentic-memory-fabric`
- metaphor: causal memory fabric. events shape memory spacetime. time and integrity shape reality.


----------------------------------------------

# Product specification: Agentic Memory Fabric

> **Note:** This project complements the educational lab in `../memory-poisoning-supply-chain`; the lab proves the problem class, this product encodes mitigations.

## 0. Charter

Build a **memory control plane** for AI agents: durable facts and procedures enter through known channels, carry **cryptographic-friendly identity**, accumulate **append-only lineage**, and are **retrieved only under policy**—with exports that are honest about what the system knows, when it learned it, and what it has retired.

**Non-charter:** This is not “a smarter prompt.” It is **infrastructure**.

## 1. Problem statement

Agent memory today often behaves like a **mutable cache with vibes**:

- Writes are high-entropy (users, tools, crawlers, migrations).
- Reads are high-entropy (similarity search, rerankers, implicit injection).
- Operators get **snapshots** (a list of notes) but not **history** (how the store became itself).

The product closes the gap between **inventory** and **audit** by making **events and lineage** first-class, and by enforcing trust transitions at the **write boundary** and **read boundary**.

## 2. Design principles

1. **Separation of concerns:** “Memory manager” vs “agent runtime / orchestration” are separate packages or services. The manager exposes APIs; the agent decides *tasks*, not *truth*.
2. **Append-only core:** The system of record is an **event log** (or log-structured merge) plus materialized views for fast retrieval.
3. **Policy is code:** Trust states are meaningless unless retrieval and prompt assembly **query** them.
4. **Deniability by construction:** If it is not in the lineage, the product does not claim it happened.
5. **Gradual adoption:** A team can start with **provenance-only** (no fancy crypto), then harden.
6. Event driven architechture (consumers, producers)

## 3. Core concepts

### 3.1 Memory record (logical)

A **memory** is an addressable object with:

- Stable `memory_id` (UUIDv7 or content-addressed id derived from initial event chain -- but prefer UUIDv7).
- `key` / logical name (optional; may be many-to-one over time).
- `payload` (string or versioned JSON schema).
- `trust_state`: `trusted` | `quarantined` | `expired` (extensible).
- `sensitivity` / `tenant_id` (for multi-tenant deployments).

### 3.2 Lineage and identity

**Lineage** is a directed acyclic graph (usually a chain) of events:

- `created`, `updated`, `superseded`, `quarantined`, `released`, `expired`, `deleted`, `imported`, `attested`

Each event includes:

- `event_id`, `timestamp` (wall + monotonic sequence), `actor` (user id, service principal, tool name + invocation id)
- `previous_events` (prior event ids)
- `payload_hash`, optional `content_address` (CID-style optional)
- Optional **`evidence_refs`**: URLs, message ids, file paths, tool run ids (opaque strings + type)

**Identity rule:** `memory_id` remains stable across content updates; content changes append new events and bump **version**.

### 3.3 Retrieval contract

Retrieval returns **candidates** with **mandatory provenance bundle**:

- current `trust_state`
- `version`
- `last_event_id`
- `why_sound` (which policy rule allowed visibility)

Retrieval must implement **hard filters**:

- Default: exclude `quarantined`, `deleted` and `expired` unless caller holds an **override capability** (auditor role, debug mode, explicit API flag).

### 3.4 Merge and conflict policy (configurable)

Product ships **pluggable resolvers**:

- **Latest-wins** (by event sequence) — dangerous but common baseline.
- **Human-gate** — conflicts create a `quarantined` branch until merged.
- **Source-rank** — e.g., `migration < tool < user_attested`.
- **Typed slots** — “only one active `API_BASE_URL` per tenant.”

The resolver is part of the control plane, not the LLM.

## 4. APIs (sketch)

**Write path**

- `ingest(event)` — append event, validate schema, run resolver hooks.
- `quarantine(memory_id, reason)`
- `release(memory_id, attestation)` — move from quarantine to trusted with evidence.
- `expire(memory_id, reason, superseded_by?)`

**Read path**

- `get(memory_id, policy_context)`
- `query(text | structured_filter, policy_context)` — vector or hybrid search *over materialized sound set*.
- `explain(memory_id)` — human-readable trace from event log.

**Export path**

- `export_sbom_snapshot(policy_context)` — JSON manifest of **sound** memories.
- `export_provenance_log(range)` — append-only slice for auditors (may include deleted).

## 5. Memory SBOM vs provenance log (honest naming)

| Artifact | Answers |
| --- | --- |
| **Memory SBOM snapshot** | What is sound to influence the agent *right now* under policy P? |
| **provenance log slice** | What happened over interval T, including quarantines, expirations, imports? |

Marketing rule: never call a snapshot a “full SBOM” if deleted and supersession live only in the log.

## 6. Decay and TTL (POC heritage)

Integrate **half-life semantics** (ticks or wall-clock; prefer ticks) as a **policy module**:

- Decay affects **soundness** (old memories may have been about something that is now deprecated, etc.) or **rank**, not historical truth.
- Expiration emits an `expired` event; the provenance-log retains the chain.

This aligns with `memory-half-life`-style POCs while keeping **expiry** distinct from **quarantine**.

## 7. Security model (realistic)

**Threats in scope**

- Poisoned content from tools/users. [OWASP ASI06: Memory & Context Poisoning](./research/OWASP-Top-10-for-Agentic-Applications-2026-12.6-1.txt)
- Accidental bad migrations.
- Retrieval bypass bugs (label ignored).
- Insider abuse (legitimate writer turns malicious).

**Out of scope (v1)**

- Full homomorphic encryption of memory payloads.
- Guaranteed model refusal (the model remains stochastic; the product reduces *unearned certainty*).

**Capabilities**

- **Writer** roles per channel.
- **Auditor** read-only access to provenance-log and quarantined content.
- **Override** explicitly logged as high-severity events.

## 8. Storage architecture (suggested phases)

**Phase 0 — library embedded in app**

- SQLite: events table + materialized `current_memory` view.
- File-based lock or single-writer assumption.

**Phase 1 — service**

- Postgres + event table partitioned by time; outbox for async index updates.
- Object storage for large blobs / attachments (payload stores hash, not giant rows).

**Phase 2 — multi-tenant**

- Row-level security, per-tenant KMS keys (optional), strict request scoping.

## 9. Integration points (keep loose coupling)

- **Python / Node** SDK first.
- Hooks for **LangGraph**, **AutoGen**, **Semantic Kernel**, etc., via thin adapters that only call `ingest` / `query` / `explain`.
- Optional **OpenTelemetry** spans: `memory.ingest`, `memory.query`, `memory.policy_denial`.

## 10. MVP acceptance criteria

1. Append-only ingest with replay-from-zero tests.
2. Retrieval denies `quarantined`/`expired`/`deleted` by default; denials are observable in telemetry.
3. `explain(memory_id)` returns ordered events including evidence refs.
4. SBOM snapshot export matches materialized sound set (golden test).
5. Import path for bulk migration produces **`imported` events** (no silent trusted writes).

## 11. Roadmap (after MVP)

- **Signed events** (developer keys, org keys) with verification at ingest.
- **Content-addressed payloads** and merkle batch provenances for “daily notarization.”
- **Federation** — cross-agent memory sharing with explicit trust domains.
- **Drift detectors** — "this memory conflicts with new external evidence" as `quarantine` suggestions, not silent overwrites.

## 12. Open questions (product research)

- How should **embedding indexes** be labeled so shadow vectors cannot bypass policy?
- What is the UX for **human merge** without turning the product into a ticket system?
- Should **model-generated summaries** be second-class memories with weaker trust by default?

---

**End state:** teams stop treating memory like a notebook and start treating it like **released software**: versioned, attributable, revocable, and exportable without lying by omission.
