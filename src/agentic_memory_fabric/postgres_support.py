"""Shared Postgres helpers for AMF backends."""

from __future__ import annotations

import re
from typing import Any


_IDENTIFIER_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")


class PostgresBackendError(RuntimeError):
    """Raised when a Postgres-backed AMF component is unavailable or unhealthy."""


def quote_identifier(value: str, *, field_name: str = "schema") -> str:
    if not _IDENTIFIER_RE.match(value):
        raise ValueError(f"{field_name} must be a valid SQL identifier")
    return '"' + value.replace('"', '""') + '"'


def load_postgres_driver() -> tuple[Any, str]:
    try:
        import psycopg  # type: ignore

        return psycopg, "psycopg"
    except ModuleNotFoundError:
        try:
            import psycopg2  # type: ignore

            return psycopg2, "psycopg2"
        except ModuleNotFoundError as exc:
            raise PostgresBackendError(
                "Postgres backend requires psycopg or psycopg2; install a PostgreSQL driver"
            ) from exc
