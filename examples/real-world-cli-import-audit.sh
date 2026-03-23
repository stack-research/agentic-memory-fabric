#!/usr/bin/env bash
set -euo pipefail

# Real-world scenario:
# - Import a migrated record
# - See default policy deny it from normal query results
# - Use explicit auditor override to inspect
# - Export explain/snapshot/provenance artifacts

DB_PATH="${DB_PATH:-.amf-prod-demo.db}"
TENANT_ID="${TENANT_ID:-tenant-acme}"
MEMORY_ID="${MEMORY_ID:-aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa}"

echo "Using DB_PATH=${DB_PATH}"
echo "Using TENANT_ID=${TENANT_ID}"
echo "Using MEMORY_ID=${MEMORY_ID}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
SRC_DIR="${REPO_ROOT}/src"
export PYTHONPATH="${SRC_DIR}${PYTHONPATH:+:${PYTHONPATH}}"

print_section() {
  local title="$1"
  echo
  echo "=== ${title} ==="
}

print_section "Import migrated record as imported event"
python3 -m agentic_memory_fabric.cli \
  --db "${DB_PATH}" \
  --tenant-id "${TENANT_ID}" \
  import-records \
  --records-json "[{\"memory_id\":\"${MEMORY_ID}\",\"payload\":{\"service\":\"payments\",\"api_base_url\":\"https://api.internal\"},\"source_id\":\"migration-2026-03\"}]" \
  --actor-json '{"id":"migration-bot","kind":"service"}' \
  --default-timestamp "2026-03-23T00:00:00Z" | python3 -m json.tool

print_section "Default query (expected deny / empty records)"
python3 -m agentic_memory_fabric.cli \
  --db "${DB_PATH}" \
  --tenant-id "${TENANT_ID}" \
  query | python3 -m json.tool

print_section "Auditor override query (shows denied-but-inspected records)"
python3 -m agentic_memory_fabric.cli \
  --db "${DB_PATH}" \
  --tenant-id "${TENANT_ID}" \
  --capabilities-json '["override_retrieval_denials"]' \
  query | python3 -m json.tool

print_section "Explain lineage for memory"
python3 -m agentic_memory_fabric.cli \
  --db "${DB_PATH}" \
  --tenant-id "${TENANT_ID}" \
  --capabilities-json '["override_retrieval_denials"]' \
  explain \
  --memory-id "${MEMORY_ID}" | python3 -m json.tool

print_section "Export snapshot (sound set under policy)"
python3 -m agentic_memory_fabric.cli \
  --db "${DB_PATH}" \
  --tenant-id "${TENANT_ID}" \
  export-snapshot | python3 -m json.tool

print_section "Export provenance log slice (full history)"
python3 -m agentic_memory_fabric.cli \
  --db "${DB_PATH}" \
  --tenant-id "${TENANT_ID}" \
  export-provenance \
  --memory-id "${MEMORY_ID}" | python3 -m json.tool
