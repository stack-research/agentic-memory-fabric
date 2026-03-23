#!/usr/bin/env bash
set -euo pipefail

# Real-world scenario:
# - Ingest trusted signed events
# - Query trusted memories via CLI
# - Join query results with source text for human-readable output
#
# Note: AMF retrieval APIs intentionally return governance metadata (not raw payload).
# This script shows an app-side enrichment pattern keyed by memory_id.

DB_PATH="${DB_PATH:-.amf-trusted-text.db}"
TENANT_ID="${TENANT_ID:-tenant-acme}"
KEY_ID="${KEY_ID:-dev-key}"
KEY_SECRET="${KEY_SECRET:-super-secret}"
TIMESTAMP="${TIMESTAMP:-2026-03-23T00:00:00Z}"
export TENANT_ID KEY_ID KEY_SECRET TIMESTAMP

echo "Using DB_PATH=${DB_PATH}"
echo "Using TENANT_ID=${TENANT_ID}"
echo "Using KEY_ID=${KEY_ID}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
SRC_DIR="${REPO_ROOT}/src"
export PYTHONPATH="${SRC_DIR}${PYTHONPATH:+:${PYTHONPATH}}"

print_section() {
  local title="$1"
  echo
  echo "=== ${title} ==="
}

print_section "Ingest trusted signed memories and print enriched trusted results"
python3 - "${DB_PATH}" <<'PY'
import hashlib
import json
import os
import subprocess
import sys

from agentic_memory_fabric.crypto import sign_event
from agentic_memory_fabric.events import EventEnvelope

db_path = sys.argv[1]
tenant_id = os.environ["TENANT_ID"]
key_id = os.environ["KEY_ID"]
key_secret = os.environ["KEY_SECRET"].encode("utf-8")
timestamp = os.environ["TIMESTAMP"]

keyring_json = json.dumps({key_id: {"key": os.environ["KEY_SECRET"], "status": "active"}})

source_memories = [
    {
        "memory_id": "11111111-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
        "text": "Payments API base URL is https://api.internal/v2",
        "source_id": "kb-001",
    },
    {
        "memory_id": "22222222-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
        "text": "Escalation contact is on-call@acme.example",
        "source_id": "kb-002",
    },
]

for i, item in enumerate(source_memories, start=1):
    payload_hash = "sha256:" + hashlib.sha256(item["text"].encode("utf-8")).hexdigest()
    event = EventEnvelope.from_dict(
        {
            "event_id": f"{i:08d}-0000-4000-8000-000000000000",
            "sequence": i,
            "timestamp": {"wall_time": timestamp, "tick": i},
            "actor": {"id": "svc-memory", "kind": "service"},
            "tenant_id": tenant_id,
            "memory_id": item["memory_id"],
            "event_type": "created",
            "previous_events": [],
            "payload_hash": payload_hash,
            "evidence_refs": [{"type": "opaque", "ref": f"import:{item['source_id']}"}],
        }
    )
    event_dict = event.to_dict()
    event_dict["signature"] = {
        "alg": "hmac-sha256",
        "key_id": key_id,
        "sig": sign_event(event, key_id=key_id, key=key_secret),
    }

    subprocess.run(
        [
            "python3",
            "-m",
            "agentic_memory_fabric.cli",
            "--db",
            db_path,
            "--tenant-id",
            tenant_id,
            "--keyring-json",
            keyring_json,
            "ingest-event",
            "--event-json",
            json.dumps(event_dict, sort_keys=True),
        ],
        check=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )

query_out = subprocess.check_output(
    [
        "python3",
        "-m",
        "agentic_memory_fabric.cli",
        "--db",
        db_path,
        "--tenant-id",
        tenant_id,
        "--keyring-json",
        keyring_json,
        "query",
    ],
    text=True,
)
query_json = json.loads(query_out)
text_by_memory_id = {item["memory_id"]: item["text"] for item in source_memories}

enriched = []
for record in query_json.get("records", []):
    enriched.append(
        {
            "memory_id": record["memory_id"],
            "text": text_by_memory_id.get(record["memory_id"], "<text not found>"),
            "trust_state": record["trust_state"],
            "signature_state": record["signature_state"],
            "version": record["version"],
            "why_sound": record["why_sound"],
        }
    )

print(
    json.dumps(
        {
            "count": len(enriched),
            "trusted_memories": enriched,
        },
        indent=2,
        sort_keys=True,
    )
)
PY
