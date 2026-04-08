"""Minimal HTTP service surface over AMF runtime."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Callable, Mapping
from urllib.parse import urlparse

from .crypto import KeyMaterial
from .runtime import MemoryRuntime, open_runtime


def _json_response(status: int, payload: dict) -> tuple[int, dict]:
    return status, payload


@dataclass
class ServiceApp:
    runtime: MemoryRuntime = field(default_factory=MemoryRuntime)
    auth_tokens: dict[str, dict[str, Any]] = field(default_factory=dict)
    audit_sink: Callable[[Mapping[str, Any]], None] | None = None

    def close(self) -> None:
        close_fn = getattr(self.runtime, "close", None)
        if callable(close_fn):
            close_fn()

    def _emit_audit(self, event: dict[str, Any]) -> None:
        if self.audit_sink is None:
            return
        self.audit_sink(dict(event))

    def _parse_json_body(self, body: bytes | None) -> dict:
        if not body:
            return {}
        return json.loads(body.decode("utf-8"))

    def _normalize_headers(self, headers: Mapping[str, str] | None) -> dict[str, str]:
        if headers is None:
            return {}
        return {str(k).lower(): str(v) for k, v in headers.items()}

    def _trusted_context_from_headers(self, headers: Mapping[str, str] | None) -> dict[str, Any] | None:
        normalized = self._normalize_headers(headers)
        token = normalized.get("x-auth-token")
        if token is None:
            return None
        claims = self.auth_tokens.get(token)
        if claims is None:
            raise ValueError("invalid auth token")
        return dict(claims)

    def _tenant_id_from_request(
        self,
        *,
        headers: Mapping[str, str] | None,
        payload: Mapping[str, Any],
    ) -> str | None:
        normalized = self._normalize_headers(headers)
        header_tenant = normalized.get("x-tenant-id")
        if header_tenant is not None and header_tenant.strip():
            return header_tenant.strip()
        policy_context = payload.get("policy_context")
        if isinstance(policy_context, Mapping):
            policy_tenant = policy_context.get("tenant_id")
            if policy_tenant is not None and str(policy_tenant).strip():
                return str(policy_tenant).strip()
        return None

    def _merge_policy_context(
        self,
        *,
        payload: Mapping[str, Any],
        tenant_id: str | None,
    ) -> dict[str, Any] | None:
        raw_policy = payload.get("policy_context")
        policy_context = dict(raw_policy) if isinstance(raw_policy, Mapping) else {}
        if tenant_id is not None:
            policy_context["tenant_id"] = tenant_id
        return policy_context or None

    def handle_request(
        self,
        method: str,
        path: str,
        body: bytes | None = None,
        headers: Mapping[str, str] | None = None,
    ) -> tuple[int, dict]:
        parsed = urlparse(path)
        route = parsed.path
        payload = self._parse_json_body(body)
        tenant_id = self._tenant_id_from_request(headers=headers, payload=payload)
        trusted_context = self._trusted_context_from_headers(headers)
        if trusted_context is not None and trusted_context.get("tenant_id") is not None:
            trusted_tenant = str(trusted_context["tenant_id"]).strip()
            if tenant_id is not None and tenant_id != trusted_tenant:
                raise ValueError("tenant mismatch between auth context and request")
            tenant_id = trusted_tenant
        policy_context = self._merge_policy_context(payload=payload, tenant_id=tenant_id)
        base_audit_event = {
            "type": "http.request",
            "http_method": method,
            "http_route": route,
            "tenant_id": tenant_id,
        }

        def respond(status: int, response_payload: dict) -> tuple[int, dict]:
            event = dict(base_audit_event)
            event["http_status"] = int(status)
            self._emit_audit(event)
            return _json_response(status, response_payload)

        if method == "POST" and route == "/ingest/event":
            event_data = payload.get("event", payload)
            event = self.runtime.ingest_event(
                event_data,
                expected_tenant_id=tenant_id,
                trusted_context=trusted_context,
            )
            return respond(HTTPStatus.OK, {"event": event.to_dict()})

        if method == "POST" and route == "/ingest/import":
            events = self.runtime.import_records(
                payload.get("records", []),
                actor=payload["actor"],
                default_timestamp=payload["default_timestamp"],
                start_sequence=payload.get("start_sequence"),
                default_tick=payload.get("default_tick"),
                tenant_id=tenant_id,
                expected_tenant_id=tenant_id,
                trusted_context=trusted_context,
            )
            return respond(
                HTTPStatus.OK,
                {"count": len(events), "events": [event.to_dict() for event in events]},
            )

        if method == "POST" and route == "/query":
            records = self.runtime.query(
                policy_context=policy_context,
                trusted_context=trusted_context,
                trust_states=set(payload["trust_states"]) if payload.get("trust_states") else None,
                limit=payload.get("limit"),
            )
            return respond(HTTPStatus.OK, {"count": len(records), "records": records})

        if method == "POST" and route.startswith("/memory/") and route.endswith("/peek"):
            parts = route.split("/")
            if len(parts) != 4:
                return _json_response(HTTPStatus.NOT_FOUND, {"error": "Not found"})
            memory_id = parts[2]
            record = self.runtime.peek(
                memory_id,
                policy_context=policy_context,
                trusted_context=trusted_context,
            )
            return respond(HTTPStatus.OK, {"memory_id": memory_id, "record": record})

        if method == "POST" and route.startswith("/memory/") and route.endswith("/recall"):
            parts = route.split("/")
            if len(parts) != 4:
                return _json_response(HTTPStatus.NOT_FOUND, {"error": "Not found"})
            memory_id = parts[2]
            result = self.runtime.recall(
                memory_id,
                actor=payload["actor"],
                policy_context=policy_context,
                trusted_context=trusted_context,
                event_id=payload.get("event_id"),
                timestamp=payload.get("timestamp"),
                evidence_refs=payload.get("evidence_refs"),
            )
            return respond(HTTPStatus.OK, {"memory_id": memory_id, **result})

        if method == "POST" and route.startswith("/memory/") and route.endswith("/reconsolidate"):
            parts = route.split("/")
            if len(parts) != 4:
                return _json_response(HTTPStatus.NOT_FOUND, {"error": "Not found"})
            memory_id = parts[2]
            result = self.runtime.reconsolidate(
                memory_id,
                actor=payload["actor"],
                payload_hash=payload["payload_hash"],
                policy_context=policy_context,
                trusted_context=trusted_context,
                event_id=payload.get("event_id"),
                timestamp=payload.get("timestamp"),
                evidence_refs=payload.get("evidence_refs"),
                signature=payload.get("signature"),
                attestation=payload.get("attestation"),
            )
            return respond(HTTPStatus.OK, {"memory_id": memory_id, **result})

        if method == "GET" and route.startswith("/memory/") and route.endswith("/explain"):
            parts = route.split("/")
            if len(parts) != 4:
                return _json_response(HTTPStatus.NOT_FOUND, {"error": "Not found"})
            memory_id = parts[2]
            trace = self.runtime.explain(
                memory_id,
                policy_context=policy_context,
                trusted_context=trusted_context,
            )
            return respond(HTTPStatus.OK, {"memory_id": memory_id, "trace": trace})

        if method == "POST" and route == "/export/snapshot":
            snapshot = self.runtime.export_snapshot(
                policy_context=policy_context,
                trusted_context=trusted_context,
            )
            return respond(HTTPStatus.OK, snapshot)

        if method == "POST" and route == "/export/provenance":
            sequence_range = payload.get("sequence_range")
            if sequence_range is not None:
                sequence_range = (int(sequence_range["start"]), int(sequence_range["end"]))
            provenance = self.runtime.export_provenance(
                policy_context=policy_context,
                trusted_context=trusted_context,
                sequence_range=sequence_range,
                memory_id=payload.get("memory_id"),
            )
            return respond(HTTPStatus.OK, provenance)

        return respond(HTTPStatus.NOT_FOUND, {"error": "Not found"})


def create_http_handler(app: ServiceApp):
    class Handler(BaseHTTPRequestHandler):
        def _dispatch(self) -> None:
            length = int(self.headers.get("Content-Length", "0") or "0")
            body = self.rfile.read(length) if length > 0 else None
            headers = {k: self.headers.get(k) for k in self.headers.keys()}
            try:
                status, payload = app.handle_request(
                    self.command,
                    self.path,
                    body,
                    headers=headers,
                )
            except Exception as exc:  # pragma: no cover - defensive boundary
                status, payload = HTTPStatus.BAD_REQUEST, {"error": str(exc)}
            encoded = json.dumps(payload, sort_keys=True).encode("utf-8")
            self.send_response(int(status))
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(encoded)))
            self.end_headers()
            self.wfile.write(encoded)

        def do_GET(self) -> None:  # noqa: N802
            self._dispatch()

        def do_POST(self) -> None:  # noqa: N802
            self._dispatch()

        def log_message(self, format: str, *args) -> None:  # noqa: A003
            return

    return Handler


def run_http_server(
    *,
    host: str = "127.0.0.1",
    port: int = 8000,
    runtime: MemoryRuntime | None = None,
    db_path: str | None = None,
    keyring: Mapping[str, bytes | str | Mapping[str, Any] | KeyMaterial] | None = None,
    audit_sink: Callable[[Mapping[str, Any]], None] | None = None,
) -> ThreadingHTTPServer:
    if runtime is not None and db_path is not None:
        raise ValueError("provide either runtime or db_path, not both")
    app_runtime = runtime or open_runtime(db_path=db_path, keyring=keyring, audit_sink=audit_sink)
    app = ServiceApp(runtime=app_runtime, audit_sink=audit_sink)
    server = ThreadingHTTPServer((host, port), create_http_handler(app))
    return server
