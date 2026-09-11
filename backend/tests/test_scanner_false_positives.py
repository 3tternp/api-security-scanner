"""
Regression tests for the false-positive reduction work in app.scanner:
- confidence_from_signals() scoring
- mass_assignment.py no longer flags a server that correctly ignores
  unknown/privileged fields (the false-positive case this rework targets),
  while still flagging a server that actually applies them (true positive).
"""
import asyncio
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from app.scanner.signals import confidence_from_signals
from app.scanner.rules.mass_assignment import MassAssignmentRule


def test_confidence_from_signals():
    assert confidence_from_signals([]) == "low"
    assert confidence_from_signals(["a"]) == "low"
    assert confidence_from_signals(["a", "b"]) == "medium"
    assert confidence_from_signals(["a", "b", "c"]) == "high"


class _SafeUserHandler(BaseHTTPRequestHandler):
    """Simulates an API that allowlists fields server-side — role/admin/etc.
    in the request body are silently dropped, never persisted."""
    resources = {}
    next_id = 1

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        body = json.loads(self.rfile.read(length) or b"{}")
        stored = {"id": _SafeUserHandler.next_id, "name": body.get("name"), "email": body.get("email")}
        _SafeUserHandler.resources[stored["id"]] = stored
        _SafeUserHandler.next_id += 1
        self._send_json(201, stored)

    def do_GET(self):
        resource_id = int(self.path.rsplit("/", 1)[-1])
        stored = _SafeUserHandler.resources.get(resource_id, {})
        self._send_json(200, stored)

    def _send_json(self, status, payload):
        body = json.dumps(payload).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format, *args):
        pass


class _VulnerableUserHandler(BaseHTTPRequestHandler):
    """Simulates an API vulnerable to mass assignment — whatever is sent is stored as-is."""
    resources = {}
    next_id = 1

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        body = json.loads(self.rfile.read(length) or b"{}")
        stored = dict(body)
        stored["id"] = _VulnerableUserHandler.next_id
        _VulnerableUserHandler.resources[stored["id"]] = stored
        _VulnerableUserHandler.next_id += 1
        self._send_json(201, stored)

    def do_GET(self):
        resource_id = int(self.path.rsplit("/", 1)[-1])
        stored = _VulnerableUserHandler.resources.get(resource_id, {})
        self._send_json(200, stored)

    def _send_json(self, status, payload):
        body = json.dumps(payload).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format, *args):
        pass


def _run_server(handler_cls):
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler_cls)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server


@pytest.mark.asyncio
async def test_mass_assignment_no_finding_when_fields_not_applied():
    server = _run_server(_SafeUserHandler)
    try:
        target_url = f"http://127.0.0.1:{server.server_port}"
        endpoints = [{"path": "/users", "method": "POST", "details": {}}]
        rule = MassAssignmentRule()
        findings = await rule.run(target_url, endpoints, {})
        assert findings == []
    finally:
        server.shutdown()


@pytest.mark.asyncio
async def test_mass_assignment_flags_when_fields_actually_applied():
    server = _run_server(_VulnerableUserHandler)
    try:
        target_url = f"http://127.0.0.1:{server.server_port}"
        endpoints = [{"path": "/users", "method": "POST", "details": {}}]
        rule = MassAssignmentRule()
        findings = await rule.run(target_url, endpoints, {})
        assert len(findings) == 1
        assert findings[0]["rule_id"] == "MASS-ASSIGN-001"
        assert "role" in findings[0]["signals"] or "injected_value_confirmed_on_refetch" in findings[0]["signals"]
    finally:
        server.shutdown()
