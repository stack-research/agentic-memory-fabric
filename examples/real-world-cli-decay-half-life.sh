#!/usr/bin/env bash
set -euo pipefail

# Real-world scenario:
# - Seed an old memory (deprecated endpoint)
# - Show policy-based decay denial at a later tick
# - Emit explicit expired event for governance state transition
# - Show default deny vs auditor override + lineage

DB_PATH="${DB_PATH:-.amf-decay-demo.db}"
TENANT_ID="${TENANT_ID:-tenant-acme}"
KEY_ID="${KEY_ID:-dev-key}"
KEY_SECRET="${KEY_SECRET:-super-secret}"
TIMESTAMP="${TIMESTAMP:-2025-03-23T00:00:00Z}"
EXPIRED_TIMESTAMP="${EXPIRED_TIMESTAMP:-2026-03-23T00:00:00Z}"
MEMORY_ID="${MEMORY_ID:-44444444-dddd-4ddd-8ddd-dddddddddddd}"
export DB_PATH TENANT_ID KEY_ID KEY_SECRET TIMESTAMP EXPIRED_TIMESTAMP MEMORY_ID

echo "Using DB_PATH=${DB_PATH}"
echo "Using TENANT_ID=${TENANT_ID}"
echo "Using MEMORY_ID=${MEMORY_ID}"
echo "Using KEY_ID=${KEY_ID}"
echo "Using TIMESTAMP=${TIMESTAMP}"
echo "Using EXPIRED_TIMESTAMP=${EXPIRED_TIMESTAMP}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
SRC_DIR="${REPO_ROOT}/src"
export PYTHONPATH="${SRC_DIR}${PYTHONPATH:+:${PYTHONPATH}}"

python3 - <<'PY'
import hashlib
import json
import os
import subprocess

from agentic_memory_fabric.crypto import sign_event
from agentic_memory_fabric.events import EventEnvelope

db_path = os.environ["DB_PATH"]
tenant_id = os.environ["TENANT_ID"]
memory_id = os.environ["MEMORY_ID"]
key_id = os.environ["KEY_ID"]
key_secret = os.environ["KEY_SECRET"].encode("utf-8")
timestamp = os.environ["TIMESTAMP"]
expired_timestamp = os.environ["EXPIRED_TIMESTAMP"]

# Reset the demo DB for deterministic reruns so event sequences remain contiguous.
if os.path.exists(db_path):
    os.remove(db_path)
    print(f"Reset existing demo DB at {db_path} for deterministic rerun.")

keyring_json = json.dumps({key_id: {"key": os.environ["KEY_SECRET"], "status": "active"}})

stale_text = "Deprecated endpoint: https://api.internal/v1 (retired one year ago)"


def run_cli(args):
    out = subprocess.check_output(
        ["python3", "-m", "agentic_memory_fabric.cli", "--db", db_path, "--tenant-id", tenant_id] + args,
        text=True,
    )
    return json.loads(out)


def ingest_signed_event(event_dict):
    run_cli(
        [
            "--keyring-json",
            keyring_json,
            "ingest-event",
            "--event-json",
            json.dumps(event_dict, sort_keys=True),
        ]
    )


def build_signed_event(
    *,
    event_id,
    sequence,
    event_type,
    previous_events,
    payload_text,
    wall_time,
    trust_transition=None,
):
    payload_hash = "sha256:" + hashlib.sha256(payload_text.encode("utf-8")).hexdigest()
    data = {
        "event_id": event_id,
        "sequence": sequence,
        "timestamp": {"wall_time": wall_time, "tick": sequence},
        "actor": {"id": "svc-memory", "kind": "service"},
        "tenant_id": tenant_id,
        "memory_id": memory_id,
        "event_type": event_type,
        "previous_events": previous_events,
        "payload_hash": payload_hash,
        "evidence_refs": [{"type": "opaque", "ref": "catalog:deprecated-api"}],
    }
    if trust_transition is not None:
        data["trust_transition"] = trust_transition
    event = EventEnvelope.from_dict(data)
    out = event.to_dict()
    out["signature"] = {
        "alg": "hmac-sha256",
        "key_id": key_id,
        "sig": sign_event(event, key_id=key_id, key=key_secret),
    }
    return out


print("\n=== Ingest trusted memory with old/deprecated endpoint ===")
created = build_signed_event(
    event_id="44444444-0000-4000-8000-000000000001",
    sequence=1,
    event_type="created",
    previous_events=[],
    payload_text=stale_text,
    wall_time=timestamp,
)
ingest_signed_event(created)

print("\n=== Default query before decay policy (still trusted) ===")
before_decay = run_cli(["--keyring-json", keyring_json, "query"])
print(json.dumps(before_decay, indent=2, sort_keys=True))

print("\n=== Query with decay policy (deny stale memory by age) ===")
decay_query = run_cli(
    [
        "--keyring-json",
        keyring_json,
        "query",
        "--policy-json",
        '{"current_tick": 400, "decay_policy": {"max_age_ticks": 365, "half_life_ticks": 180}}',
    ]
)
print(json.dumps(decay_query, indent=2, sort_keys=True))

print("\n=== Emit explicit expired event (governance transition) ===")
expired = build_signed_event(
    event_id="44444444-0000-4000-8000-000000000002",
    sequence=2,
    event_type="expired",
    previous_events=[created["event_id"]],
    payload_text=stale_text,
    wall_time=expired_timestamp,
    trust_transition={"to": "expired", "reason": "stale_endpoint_one_year_old"},
)
ingest_signed_event(expired)

print("\n=== Default query after explicit expiration ===")
after_expire = run_cli(["--keyring-json", keyring_json, "query"])
print(json.dumps(after_expire, indent=2, sort_keys=True))

print("\n=== Auditor override query after expiration ===")
override_query = run_cli(
    [
        "--keyring-json",
        keyring_json,
        "--capabilities-json",
        '["override_retrieval_denials"]',
        "query",
    ]
)
print(json.dumps(override_query, indent=2, sort_keys=True))

print("\n=== Enriched stale-memory view ===")
enriched = []
for rec in override_query.get("records", []):
    enriched.append(
        {
            "memory_id": rec["memory_id"],
            "text": stale_text,
            "trust_state": rec["trust_state"],
            "denial_reason": rec["denial_reason"],
            "override_used": rec["override_used"],
            "why_sound": rec["why_sound"],
        }
    )
print(json.dumps({"count": len(enriched), "records": enriched}, indent=2, sort_keys=True))

print("\n=== Lineage explain (created -> expired) ===")
trace = run_cli(
    [
        "--keyring-json",
        keyring_json,
        "--capabilities-json",
        '["override_retrieval_denials"]',
        "explain",
        "--memory-id",
        memory_id,
    ]
)
print(json.dumps(trace, indent=2, sort_keys=True))
PY
