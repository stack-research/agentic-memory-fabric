"""Conflict-resolution helpers for AMF."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass

from .events import canonical_json_dumps


DEFAULT_RESOLVER_KIND = "human_gate"


@dataclass(frozen=True)
class ConflictAssessment:
    memory_id: str
    related_memory_id: str
    tenant_id: str | None
    source_event_ids: tuple[str, ...]
    conflict_set_id: str | None
    resolvable: bool
    denial_reason: str | None
    override_used: bool


def stable_conflict_set_id(memory_ids: list[str] | tuple[str, ...]) -> str:
    normalized = tuple(sorted({str(memory_id) for memory_id in memory_ids}))
    digest = hashlib.sha256(canonical_json_dumps(normalized).encode("utf-8")).hexdigest()
    return f"conflictset:{digest}"
