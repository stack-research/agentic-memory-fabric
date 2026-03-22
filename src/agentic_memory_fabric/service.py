"""Minimal HTTP service surface over AMF runtime."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse

from .runtime import MemoryRuntime, open_runtime


def _json_response(status: int, payload: dict) -> tuple[int, dict]:
    return status, payload


@dataclass
class ServiceApp:
    runtime: MemoryRuntime = field(default_factory=MemoryRuntime)

    def _parse_json_body(self, body: bytes | None) -> dict:
        if not body:
            return {}
        return json.loads(body.decode("utf-8"))

    def handle_request(self, method: str, path: str, body: bytes | None = None) -> tuple[int, dict]:
        parsed = urlparse(path)
        route = parsed.path
        payload = self._parse_json_body(body)

        if method == "POST" and route == "/ingest/event":
            event_data = payload.get("event", payload)
            event = self.runtime.ingest_event(event_data)
            return _json_response(HTTPStatus.OK, {"event": event.to_dict()})

        if method == "POST" and route == "/ingest/import":
            events = self.runtime.import_records(
                payload.get("records", []),
                actor=payload["actor"],
                default_timestamp=payload["default_timestamp"],
                start_sequence=payload.get("start_sequence"),
                default_tick=payload.get("default_tick"),
            )
            return _json_response(
                HTTPStatus.OK,
                {"count": len(events), "events": [event.to_dict() for event in events]},
            )

        if method == "POST" and route == "/query":
            records = self.runtime.query(
                policy_context=payload.get("policy_context"),
                trust_states=set(payload["trust_states"]) if payload.get("trust_states") else None,
                limit=payload.get("limit"),
            )
            return _json_response(HTTPStatus.OK, {"count": len(records), "records": records})

        if method == "GET" and route.startswith("/memory/") and route.endswith("/explain"):
            parts = route.split("/")
            if len(parts) != 4:
                return _json_response(HTTPStatus.NOT_FOUND, {"error": "Not found"})
            memory_id = parts[2]
            trace = self.runtime.explain(memory_id)
            return _json_response(HTTPStatus.OK, {"memory_id": memory_id, "trace": trace})

        if method == "POST" and route == "/export/snapshot":
            snapshot = self.runtime.export_snapshot(policy_context=payload.get("policy_context"))
            return _json_response(HTTPStatus.OK, snapshot)

        if method == "POST" and route == "/export/provenance":
            sequence_range = payload.get("sequence_range")
            if sequence_range is not None:
                sequence_range = (int(sequence_range["start"]), int(sequence_range["end"]))
            provenance = self.runtime.export_provenance(
                sequence_range=sequence_range,
                memory_id=payload.get("memory_id"),
            )
            return _json_response(HTTPStatus.OK, provenance)

        return _json_response(HTTPStatus.NOT_FOUND, {"error": "Not found"})


def create_http_handler(app: ServiceApp):
    class Handler(BaseHTTPRequestHandler):
        def _dispatch(self) -> None:
            length = int(self.headers.get("Content-Length", "0") or "0")
            body = self.rfile.read(length) if length > 0 else None
            try:
                status, payload = app.handle_request(self.command, self.path, body)
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
) -> ThreadingHTTPServer:
    if runtime is not None and db_path is not None:
        raise ValueError("provide either runtime or db_path, not both")
    app_runtime = runtime or open_runtime(db_path=db_path)
    app = ServiceApp(runtime=app_runtime)
    server = ThreadingHTTPServer((host, port), create_http_handler(app))
    return server
