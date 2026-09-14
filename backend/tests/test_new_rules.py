"""
Tests for the new low-false-positive rules: TRACE-METHOD-001,
METHOD-OVERRIDE-001, GRAPHQL-INTROSPECTION, and ERROR-DISCLOSURE.

Each rule gets a "vulnerable" server that should produce exactly the
intended finding, and a "safe" server shaped to look superficially similar
but that should produce no finding at all — the false-positive case each
rule was specifically designed to avoid.
"""
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from app.scanner.rules.trace_method import TraceMethodRule
from app.scanner.rules.method_override import MethodOverrideRule
from app.scanner.rules.graphql_introspection import GraphQLIntrospectionRule
from app.scanner.rules.error_disclosure import ErrorDisclosureRule


def _run_server(handler_cls):
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler_cls)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server


def _send_json(handler, status, payload):
    body = json.dumps(payload).encode()
    handler.send_response(status)
    handler.send_header("Content-Type", "application/json")
    handler.send_header("Content-Length", str(len(body)))
    handler.end_headers()
    handler.wfile.write(body)


# --- TRACE-METHOD-001 ------------------------------------------------------

class _TraceEnabledHandler(BaseHTTPRequestHandler):
    def do_TRACE(self):
        # Echo the raw request line + headers back, like a server with TRACE
        # support naively enabled.
        lines = [f"TRACE {self.path} HTTP/1.1"]
        for k, v in self.headers.items():
            lines.append(f"{k}: {v}")
        body = "\r\n".join(lines).encode()
        self.send_response(200)
        self.send_header("Content-Type", "message/http")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        _send_json(self, 200, {"ok": True})

    def log_message(self, format, *args):
        pass


class _TraceDisabledHandler(BaseHTTPRequestHandler):
    def do_TRACE(self):
        self.send_response(405)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def do_GET(self):
        _send_json(self, 200, {"ok": True})

    def log_message(self, format, *args):
        pass


@pytest.mark.asyncio
async def test_trace_method_flags_when_canary_echoed():
    server = _run_server(_TraceEnabledHandler)
    try:
        target_url = f"http://127.0.0.1:{server.server_port}"
        endpoints = [{"path": "/", "method": "GET", "details": {}}]
        rule = TraceMethodRule()
        findings = await rule.run(target_url, endpoints, {})
        assert len(findings) == 1
        assert findings[0]["rule_id"] == "TRACE-METHOD-001"
        assert "trace_request_echoed_canary_header" in findings[0]["signals"]
    finally:
        server.shutdown()


@pytest.mark.asyncio
async def test_trace_method_no_finding_when_disabled():
    server = _run_server(_TraceDisabledHandler)
    try:
        target_url = f"http://127.0.0.1:{server.server_port}"
        endpoints = [{"path": "/", "method": "GET", "details": {}}]
        rule = TraceMethodRule()
        findings = await rule.run(target_url, endpoints, {})
        assert findings == []
    finally:
        server.shutdown()


# --- METHOD-OVERRIDE-001 ----------------------------------------------------

class _MethodOverrideVulnerableHandler(BaseHTTPRequestHandler):
    """DELETE is properly denied with no credentials, but a POST carrying a
    method-override header is dispatched straight to the delete handler."""

    def _read_body(self):
        length = int(self.headers.get("Content-Length", 0))
        if length:
            self.rfile.read(length)

    def do_DELETE(self):
        self._read_body()
        _send_json(self, 401, {"error": "unauthorized"})

    def do_POST(self):
        self._read_body()
        override = (
            self.headers.get("X-HTTP-Method-Override")
            or self.headers.get("X-HTTP-Method")
            or self.headers.get("X-Method-Override")
        )
        if override and override.upper() == "DELETE":
            _send_json(self, 200, {"deleted": True})
        else:
            _send_json(self, 401, {"error": "unauthorized"})

    def log_message(self, format, *args):
        pass


class _MethodOverrideSafeHandler(BaseHTTPRequestHandler):
    """Denies DELETE, and does not honor any override header on POST."""

    def _read_body(self):
        length = int(self.headers.get("Content-Length", 0))
        if length:
            self.rfile.read(length)

    def do_DELETE(self):
        self._read_body()
        _send_json(self, 401, {"error": "unauthorized"})

    def do_POST(self):
        self._read_body()
        _send_json(self, 401, {"error": "unauthorized"})

    def log_message(self, format, *args):
        pass


@pytest.mark.asyncio
async def test_method_override_flags_real_bypass():
    server = _run_server(_MethodOverrideVulnerableHandler)
    try:
        target_url = f"http://127.0.0.1:{server.server_port}"
        endpoints = [{"path": "/users/1", "method": "DELETE", "details": {}}]
        rule = MethodOverrideRule()
        findings = await rule.run(target_url, endpoints, {})
        assert len(findings) == 1
        assert findings[0]["rule_id"] == "METHOD-OVERRIDE-001"
        assert "real_method_denied" in findings[0]["signals"]
        assert "control_post_without_override_denied" in findings[0]["signals"]
    finally:
        server.shutdown()


@pytest.mark.asyncio
async def test_method_override_no_finding_when_not_honored():
    server = _run_server(_MethodOverrideSafeHandler)
    try:
        target_url = f"http://127.0.0.1:{server.server_port}"
        endpoints = [{"path": "/users/1", "method": "DELETE", "details": {}}]
        rule = MethodOverrideRule()
        findings = await rule.run(target_url, endpoints, {})
        assert findings == []
    finally:
        server.shutdown()


# --- GRAPHQL-INTROSPECTION ---------------------------------------------------

class _GraphQLHandler(BaseHTTPRequestHandler):
    def do_POST(self):
        if self.path != "/graphql":
            _send_json(self, 404, {"error": "not found"})
            return
        length = int(self.headers.get("Content-Length", 0))
        body = json.loads(self.rfile.read(length) or b"{}")
        query = body.get("query", "")
        if "__schema" in query:
            _send_json(self, 200, {
                "data": {
                    "__schema": {
                        "queryType": {"name": "Query"},
                        "types": [{"name": f"Type{i}"} for i in range(15)],
                    }
                }
            })
        else:
            _send_json(self, 200, {"data": {}})

    def log_message(self, format, *args):
        pass


class _PlainRestHandler(BaseHTTPRequestHandler):
    """A normal REST API with no /graphql route at all."""

    def do_POST(self):
        _send_json(self, 404, {"error": "not found"})

    def log_message(self, format, *args):
        pass


@pytest.mark.asyncio
async def test_graphql_introspection_flags_exposed_schema():
    server = _run_server(_GraphQLHandler)
    try:
        target_url = f"http://127.0.0.1:{server.server_port}"
        rule = GraphQLIntrospectionRule()
        findings = await rule.run(target_url, [], {})
        assert len(findings) == 1
        assert findings[0]["rule_id"] == "GRAPHQL-INTROSPECTION"
        assert findings[0]["details"]["type_count"] == 15
    finally:
        server.shutdown()


@pytest.mark.asyncio
async def test_graphql_introspection_no_finding_on_plain_rest_api():
    server = _run_server(_PlainRestHandler)
    try:
        target_url = f"http://127.0.0.1:{server.server_port}"
        rule = GraphQLIntrospectionRule()
        findings = await rule.run(target_url, [], {})
        assert findings == []
    finally:
        server.shutdown()


# --- ERROR-DISCLOSURE --------------------------------------------------------

class _DebugModeHandler(BaseHTTPRequestHandler):
    MALFORMED = {'{"malformed": ', '{"a": [1,2,3,}'}

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        raw = self.rfile.read(length).decode("utf-8", "ignore") if length else ""
        if raw in self.MALFORMED:
            body = (
                "Traceback (most recent call last):\n"
                '  File "app.py", line 42, in handler\n'
                "    json.loads(raw)\n"
                "json.decoder.JSONDecodeError: Expecting value"
            ).encode()
            self.send_response(500)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        else:
            _send_json(self, 201, {"ok": True})

    def log_message(self, format, *args):
        pass


class _GenericErrorHandler(BaseHTTPRequestHandler):
    """Returns a generic error for malformed input instead of a stack trace."""

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        if length:
            self.rfile.read(length)
        _send_json(self, 400, {"error": "invalid request"})

    def log_message(self, format, *args):
        pass


@pytest.mark.asyncio
async def test_error_disclosure_flags_stack_trace():
    server = _run_server(_DebugModeHandler)
    try:
        target_url = f"http://127.0.0.1:{server.server_port}"
        endpoints = [{"path": "/orders", "method": "POST", "details": {}}]
        rule = ErrorDisclosureRule()
        findings = await rule.run(target_url, endpoints, {})
        assert len(findings) == 1
        assert findings[0]["rule_id"] == "ERROR-DISCLOSURE"
        assert len(findings[0]["signals"]) >= 2
    finally:
        server.shutdown()


@pytest.mark.asyncio
async def test_error_disclosure_no_finding_on_generic_error():
    server = _run_server(_GenericErrorHandler)
    try:
        target_url = f"http://127.0.0.1:{server.server_port}"
        endpoints = [{"path": "/orders", "method": "POST", "details": {}}]
        rule = ErrorDisclosureRule()
        findings = await rule.run(target_url, endpoints, {})
        assert findings == []
    finally:
        server.shutdown()
