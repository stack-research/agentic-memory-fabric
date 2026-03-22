# Agentic Memory Fabric

Agentic Memory Fabric is a memory control plane for AI systems. It treats durable memory as governed infrastructure, not prompt tricks: append-only events form lineage, policy gates retrieval, and exports distinguish current sound state from historical truth.

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
