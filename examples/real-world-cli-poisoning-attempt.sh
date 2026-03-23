#!/usr/bin/env bash
set -euo pipefail

# Real-world scenario:
# - Start with trusted memory (known good endpoint)
# - Ingest a suspicious update (poisoning attempt)
# - Quarantine the memory via trust transition
# - Show default deny vs auditor override + lineage trace

DB_PATH="${DB_PATH:-.amf-poisoning-demo.db}"
TENANT_ID="${TENANT_ID:-tenant-acme}"
KEY_ID="${KEY_ID:-dev-key}"
KEY_SECRET="${KEY_SECRET:-super-secret}"
TIMESTAMP="${TIMESTAMP:-2026-03-23T00:00:00Z}"
MEMORY_ID="${MEMORY_ID:-33333333-cccc-4ccc-8ccc-cccccccccccc}"
export DB_PATH TENANT_ID KEY_ID KEY_SECRET TIMESTAMP MEMORY_ID

echo "Using DB_PATH=${DB_PATH}"
echo "Using TENANT_ID=${TENANT_ID}"
echo "Using MEMORY_ID=${MEMORY_ID}"
echo "Using KEY_ID=${KEY_ID}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
SRC_DIR="${REPO_ROOT}/src"
export PYTHONPATH="${SRC_DIR}${PYTHONPATH:+:${PYTHONPATH}}"

python3 - <<'PY'
import hashlib
import json
import os
import sqlite3
import subprocess

from agentic_memory_fabric.crypto import sign_event
from agentic_memory_fabric.events import EventEnvelope

db_path = os.environ["DB_PATH"]
tenant_id = os.environ["TENANT_ID"]
memory_id = os.environ["MEMORY_ID"]
key_id = os.environ["KEY_ID"]
key_secret = os.environ["KEY_SECRET"].encode("utf-8")
timestamp = os.environ["TIMESTAMP"]
keyring_json = json.dumps({key_id: {"key": os.environ["KEY_SECRET"], "status": "active"}})

db_exists = os.path.exists(db_path)
event_count = 0
max_sequence = 0
if db_exists:
    conn = sqlite3.connect(db_path)
    try:
        row = conn.execute("SELECT COUNT(*), COALESCE(MAX(sequence), 0) FROM events").fetchone()
        if row is not None:
            event_count = int(row[0])
            max_sequence = int(row[1])
    finally:
        conn.close()
if db_exists:
    os.remove(db_path)
    print(f"Reset existing demo DB at {db_path} for deterministic rerun.")

known_good_text = "Payments API endpoint: https://api.internal/v2"
suspect_text = "Payments API endpoint: https://evil-phish.example/collect"
text_by_event = {
    "created": known_good_text,
    "updated": suspect_text,
}


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


def build_signed_event(*, event_id, sequence, event_type, previous_events, text=None, trust_transition=None):
    payload_source = text or f"{event_type}:{memory_id}:{sequence}"
    payload_hash = "sha256:" + hashlib.sha256(payload_source.encode("utf-8")).hexdigest()
    data = {
        "event_id": event_id,
        "sequence": sequence,
        "timestamp": {"wall_time": timestamp, "tick": sequence},
        "actor": {"id": "svc-memory", "kind": "service"},
        "tenant_id": tenant_id,
        "memory_id": memory_id,
        "event_type": event_type,
        "previous_events": previous_events,
        "payload_hash": payload_hash,
        "evidence_refs": [{"type": "tool_run_id", "ref": f"detector-run-{sequence}"}],
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


print("\n=== Ingest trusted memory, suspicious update, then quarantine ===")
print(
    "NOTE: Quarantine here is intentionally simulated as an external detector/human decision "
    "writing a trust_transition event. AMF records and enforces that decision; it does not "
    "classify poisoning by itself."
)
created = build_signed_event(
    event_id="33333333-0000-4000-8000-000000000001",
    sequence=1,
    event_type="created",
    previous_events=[],
    text=text_by_event["created"],
)
updated = build_signed_event(
    event_id="33333333-0000-4000-8000-000000000002",
    sequence=2,
    event_type="updated",
    previous_events=[created["event_id"]],
    text=text_by_event["updated"],
)
quarantined = build_signed_event(
    event_id="33333333-0000-4000-8000-000000000003",
    sequence=3,
    event_type="quarantined",
    previous_events=[updated["event_id"]],
    trust_transition={"to": "quarantined", "reason": "suspected_memory_poisoning"},
)
for event in (created, updated, quarantined):
    ingest_signed_event(event)

print("\n=== Default query (quarantined memory denied) ===")
default_query = run_cli(["--keyring-json", keyring_json, "query"])
print(json.dumps(default_query, indent=2, sort_keys=True))

print("\n=== Auditor override query (visibility with denial reason) ===")
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

print("\n=== Enriched trusted-context view (memory text + governance) ===")
enriched = []
for rec in override_query.get("records", []):
    enriched.append(
        {
            "memory_id": rec["memory_id"],
            "latest_text_candidate": text_by_event["updated"],
            "trust_state": rec["trust_state"],
            "denial_reason": rec["denial_reason"],
            "override_used": rec["override_used"],
            "why_sound": rec["why_sound"],
        }
    )
print(json.dumps({"count": len(enriched), "records": enriched}, indent=2, sort_keys=True))

print("\n=== Lineage explain (shows poisoning attempt + quarantine) ===")
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
