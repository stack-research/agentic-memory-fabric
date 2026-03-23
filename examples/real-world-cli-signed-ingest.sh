#!/usr/bin/env bash
set -euo pipefail

# Real-world scenario:
# - Produce a signed event (HMAC-SHA256)
# - Ingest it with a runtime keyring
# - Query under default policy and confirm signature verification

DB_PATH="${DB_PATH:-.amf-signed-demo.db}"
TENANT_ID="${TENANT_ID:-tenant-acme}"
MEMORY_ID="${MEMORY_ID:-bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb}"
KEY_ID="${KEY_ID:-dev-key}"
KEY_SECRET="${KEY_SECRET:-super-secret}"
TIMESTAMP="${TIMESTAMP:-2026-03-23T00:00:00Z}"
export TENANT_ID MEMORY_ID KEY_ID KEY_SECRET TIMESTAMP

echo "Using DB_PATH=${DB_PATH}"
echo "Using TENANT_ID=${TENANT_ID}"
echo "Using MEMORY_ID=${MEMORY_ID}"
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

print_section "Build signed event payload (HMAC-SHA256)"
EVENT_JSON="$(
python3 - <<'PY'
import json
import os

from agentic_memory_fabric.crypto import sign_event
from agentic_memory_fabric.events import EventEnvelope

memory_id = os.environ["MEMORY_ID"]
key_id = os.environ["KEY_ID"]
key_secret = os.environ["KEY_SECRET"].encode("utf-8")
timestamp = os.environ["TIMESTAMP"]

event = EventEnvelope.from_dict(
    {
        "event_id": "cccccccc-cccc-4ccc-8ccc-cccccccccccc",
        "sequence": 1,
        "timestamp": {"wall_time": timestamp, "tick": 1},
        "actor": {"id": "svc-memory", "kind": "service"},
        "tenant_id": os.environ["TENANT_ID"],
        "memory_id": memory_id,
        "event_type": "created",
        "previous_events": [],
        "payload_hash": "sha256:" + ("a" * 64),
    }
)

event_dict = event.to_dict()
event_dict["signature"] = {
    "alg": "hmac-sha256",
    "key_id": key_id,
    "sig": sign_event(event, key_id=key_id, key=key_secret),
}
print(json.dumps(event_dict, sort_keys=True))
PY
)"

print_section "Ingest signed event"
python3 -m agentic_memory_fabric.cli \
  --db "${DB_PATH}" \
  --tenant-id "${TENANT_ID}" \
  --keyring-json "{\"${KEY_ID}\":{\"key\":\"${KEY_SECRET}\",\"status\":\"active\"}}" \
  ingest-event \
  --event-json "${EVENT_JSON}" | python3 -m json.tool

print_section "Default query (should show verified signature_state)"
python3 -m agentic_memory_fabric.cli \
  --db "${DB_PATH}" \
  --tenant-id "${TENANT_ID}" \
  --keyring-json "{\"${KEY_ID}\":{\"key\":\"${KEY_SECRET}\",\"status\":\"active\"}}" \
  query | python3 -m json.tool
