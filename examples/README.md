# CLI Examples Walkthrough

This folder contains runnable, human-readable CLI walkthroughs.

## Prerequisites

- Run from repo root.
- Use `python3`.
- No install step is required for these scripts; they set `PYTHONPATH` to `src`.

## Example 1: Import + Audit Flow

Script: `examples/real-world-cli-import-audit.sh`

Run:

```bash
./examples/real-world-cli-import-audit.sh
```

What it demonstrates:

1. **Import migrated record** via `import-records`.
2. **Default query deny** (record is not in the default sound set).
3. **Auditor override query** with `override_retrieval_denials`.
4. **Lineage explain** for one `memory_id`.
5. **Snapshot export** (what is sound now).
6. **Provenance export** (historical event trail).

How to read output quickly:

- `count`: number of returned records/events.
- `records`: retrieval-facing entries (policy-gated materialized view).
- `events`: append-only event history (provenance).
- `denial_reason`: why a record was denied under default policy.
- `override_used`: `true` when auditor capability surfaced denied content.
- `why_sound`: reason a record is allowed under current policy.

Important note:

- You will not see raw payload text in retrieval output. This example focuses on governance metadata (`trust_state`, `version`, `signature_state`, policy reasons) and lineage.

## Example 2: Signed Ingest Flow

Script: `examples/real-world-cli-signed-ingest.sh`

Run:

```bash
./examples/real-world-cli-signed-ingest.sh
```

What it demonstrates:

1. Build a signed `created` event (`hmac-sha256`).
2. Ingest with `--keyring-json`.
3. Query with default policy and inspect signature verification fields.

How to read output quickly:

- `signature_state`: verification result (for example `verified`).
- `version`: current memory version from replay/materialized state.
- `last_event_id`: latest lineage pointer.

## Example 3: Trusted Memories + Text (Enriched)

Script: `examples/real-world-cli-trusted-text.sh`

Run:

```bash
./examples/real-world-cli-trusted-text.sh
```

What it demonstrates:

1. Ingest two trusted, signed memories.
2. Query trusted records through the CLI.
3. Enrich query output with memory text from an app-side source map (`memory_id -> text`).

Why this pattern exists:

- AMF retrieval returns governance metadata by design.
- If your product needs raw text in a UI/report, join on `memory_id` from your source/content store.

## Example 4: Memory Poisoning Attempt + Quarantine

Script: `examples/real-world-cli-poisoning-attempt.sh`

Run:

```bash
./examples/real-world-cli-poisoning-attempt.sh
```

What it demonstrates:

1. Ingest trusted memory with known-good text.
2. Ingest suspicious update (poisoning attempt).
3. Quarantine via explicit `trust_transition`.
4. Show default deny, then auditor override visibility.
5. Show lineage with `created -> updated -> quarantined`.

Control-plane boundary (important):

- In this demo, quarantine is triggered as a simulated external decision (detector or human reviewer).
- AMF does not decide if memory is poisoned; it stores the decision as an event and enforces retrieval policy.

How to read output quickly:

- Default query should return `count: 0`.
- Override query should return the memory with:
  - `trust_state: quarantined`
  - `denial_reason: quarantined_memory_default_deny`
  - `override_used: true`

## Example 5: Decay / Half-Life + Explicit Expiration

Script: `examples/real-world-cli-decay-half-life.sh`

Run:

```bash
./examples/real-world-cli-decay-half-life.sh
```

What it demonstrates:

1. Ingest a trusted but stale memory (deprecated endpoint).
2. Apply decay policy in query (`current_tick` + `decay_policy`) to deny stale retrieval.
3. Emit explicit `expired` event with trust transition.
4. Show default deny after expiration and auditor override visibility.
5. Show lineage with `created -> expired`.

Control-plane boundary (important):

- Decay/expiration policy can deny retrieval by freshness.
- Emitting an explicit `expired` event is still a governance action that AMF records and enforces.

How to read output quickly:

- Decay-policy query should return `count: 0` once age exceeds policy.
- Post-expiration override query should include:
  - `trust_state: expired`
  - `denial_reason: expired_memory_default_deny`
  - `override_used: true`

## Useful overrides

All scripts support environment variable overrides:

```bash
DB_PATH=.amf-demo.db TENANT_ID=tenant-acme MEMORY_ID=aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa ./examples/real-world-cli-import-audit.sh
```

Signed flows also support:

```bash
KEY_ID=dev-key KEY_SECRET=super-secret ./examples/real-world-cli-signed-ingest.sh
```
