"""Semantic query backends and deterministic local embedding helpers."""

from __future__ import annotations

import hashlib
import math
import re
from dataclasses import dataclass
from typing import TYPE_CHECKING, Mapping, Protocol

if TYPE_CHECKING:
    from .replay import MemoryState


_TOKEN_RE = re.compile(r"[A-Za-z0-9_]+")
DEFAULT_EMBEDDING_DIMENSION = 16


def tokenize_text(value: str) -> tuple[str, ...]:
    return tuple(match.group(0).lower() for match in _TOKEN_RE.finditer(value))


@dataclass(frozen=True)
class QueryIndexEntry:
    tenant_id: str
    memory_id: str
    indexed_event_id: str
    memory_class: str
    trust_state: str
    retrieval_text: str
    indexed_sequence: int


@dataclass(frozen=True)
class SearchHit:
    tenant_id: str
    memory_id: str
    indexed_event_id: str
    retrieval_score: float
    retrieval_mode: str


class QueryBackendError(RuntimeError):
    """Raised when the semantic query backend is unavailable or unhealthy."""


class TextEmbedder(Protocol):
    dimension: int

    def embed_text(self, text: str) -> list[float]: ...


class QueryBackend(Protocol):
    name: str

    def search(
        self,
        *,
        query_text: str,
        tenant_id: str | None,
        memory_class: str | None = None,
        limit: int | None = None,
    ) -> list[SearchHit]: ...

    def refresh(
        self,
        state_map: Mapping[str, MemoryState],
        *,
        memory_ids: tuple[str, ...] | None = None,
    ) -> None: ...

    def close(self) -> None: ...


class DeterministicTextEmbedder:
    """Stable local embedder for tests and offline development."""

    dimension = DEFAULT_EMBEDDING_DIMENSION

    def embed_text(self, text: str) -> list[float]:
        vector = [0.0] * self.dimension
        tokens = tokenize_text(text)
        if not tokens:
            return vector
        for token in tokens:
            digest = hashlib.sha256(token.encode("utf-8")).digest()
            for offset in range(4):
                bucket = digest[offset] % self.dimension
                sign = 1.0 if digest[offset + 4] % 2 == 0 else -1.0
                vector[bucket] += sign
        norm = math.sqrt(sum(value * value for value in vector))
        if norm == 0.0:
            return vector
        return [round(value / norm, 6) for value in vector]


class InMemoryQueryIndex:
    name = "inmemory"

    def __init__(self, entries: tuple[QueryIndexEntry, ...]) -> None:
        self._entries = entries

    @classmethod
    def build(cls, state_map: Mapping[str, MemoryState]) -> "InMemoryQueryIndex":
        entries: list[QueryIndexEntry] = []
        for state in sorted(state_map.values(), key=lambda item: item.last_sequence):
            if not state.queryable_payload_present or not state.retrieval_text:
                continue
            entries.append(
                QueryIndexEntry(
                    tenant_id=state.tenant_id,
                    memory_id=state.memory_id,
                    indexed_event_id=state.last_event_id,
                    memory_class=state.memory_class,
                    trust_state=state.trust_state,
                    retrieval_text=state.retrieval_text,
                    indexed_sequence=state.last_sequence,
                )
            )
        return cls(tuple(entries))

    def search(
        self,
        *,
        query_text: str,
        tenant_id: str | None,
        memory_class: str | None = None,
        limit: int | None = None,
    ) -> list[SearchHit]:
        if limit is not None and limit < 1:
            raise ValueError("limit must be >= 1 when provided")
        query_tokens = tokenize_text(query_text)
        if not query_tokens:
            return []
        query_token_set = set(query_tokens)
        needle = query_text.strip().lower()
        hits: list[SearchHit] = []
        for entry in self._entries:
            if tenant_id is not None and entry.tenant_id != tenant_id:
                continue
            if memory_class is not None and entry.memory_class != memory_class:
                continue
            entry_tokens = tokenize_text(entry.retrieval_text)
            if not entry_tokens:
                continue
            overlap = len(query_token_set.intersection(entry_tokens))
            if overlap == 0 and needle not in entry.retrieval_text.lower():
                continue
            score = overlap / len(query_token_set)
            if needle and needle in entry.retrieval_text.lower():
                score += 0.25
            hits.append(
                SearchHit(
                    tenant_id=entry.tenant_id,
                    memory_id=entry.memory_id,
                    indexed_event_id=entry.indexed_event_id,
                    retrieval_score=round(score, 6),
                    retrieval_mode="lexical_v1",
                )
            )
        hits.sort(
            key=lambda item: (
                -item.retrieval_score,
                item.memory_id,
                item.indexed_event_id,
            )
        )
        if limit is not None:
            return hits[:limit]
        return hits

    def refresh(
        self,
        state_map: Mapping[str, MemoryState],
        *,
        memory_ids: tuple[str, ...] | None = None,
    ) -> None:
        del memory_ids
        rebuilt = self.build(state_map)
        self._entries = rebuilt._entries

    def close(self) -> None:
        return


InMemoryQueryBackend = InMemoryQueryIndex
QueryIndex = QueryBackend
