"""
Regression tests for precision fixes in app.scanner:
- OPENAPI-CONTRACT no longer flags every operation as missing auth when a
  spec declares 'security' globally at the document root (the standard,
  recommended pattern) instead of repeating it on each operation.
- HTML-INJ-001 only flags a payload that was actually reflected, not any
  response that happens to contain an unrelated marker from the payload set
  (e.g. a normal page's own <script> tag).
- SENSITIVE-DATA ignores placeholder/example emails.
- PATH-TRAV-001 requires a distinctive marker (or several weak ones
  together) rather than a single easily-coincidental substring.
"""
import asyncio
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from app.scanner.engine import ScannerEngine
from app.scanner.rules.openapi_contract import OpenAPIContractRule
from app.scanner.rules.html_injection import HTMLInjectionRule
from app.scanner.rules.sensitive_data import SensitiveDataRule
from app.scanner.rules.path_traversal import PathTraversalRule


def _run_server(handler_cls):
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler_cls)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server


def test_global_security_does_not_flag_every_operation():
    engine = ScannerEngine.__new__(ScannerEngine)  # no db needed for parse_endpoints
    spec = {
        "security": [{"bearerAuth": []}],
        "paths": {
            "/orders": {
                "post": {"summary": "create order"},
            }
        },
    }
    endpoints = engine.parse_endpoints(spec)
    assert endpoints[0]["details"]["_global_security_defined"] is True


@pytest.mark.asyncio
async def test_openapi_contract_no_finding_with_global_security():
    engine = ScannerEngine.__new__(ScannerEngine)
    spec = {
        "security": [{"bearerAuth": []}],
        "paths": {
            "/orders": {"post": {"summary": "create order"}},
        },
    }
    endpoints = engine.parse_endpoints(spec)
    rule = OpenAPIContractRule()
    findings = await rule.run("http://example.com", endpoints, {})
    assert findings == []


@pytest.mark.asyncio
async def test_openapi_contract_still_flags_when_no_security_anywhere():
    engine = ScannerEngine.__new__(ScannerEngine)
    spec = {
        "paths": {
            "/orders": {"post": {"summary": "create order"}},
        },
    }
    endpoints = engine.parse_endpoints(spec)
    rule = OpenAPIContractRule()
    findings = await rule.run("http://example.com", endpoints, {})
    assert len(findings) == 1
    assert findings[0]["rule_id"] == "OPENAPI-CONTRACT"


class _PlainPageHandler(BaseHTTPRequestHandler):
    """A normal HTML page that legitimately contains a <script> tag (as
    almost every real page does) but reflects nothing from the request."""

    def do_GET(self):
        body = b"<html><body><h1>Welcome</h1><script>console.log('ok')</script></body></html>"
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format, *args):
        pass


class _ReflectingPageHandler(BaseHTTPRequestHandler):
    """Echoes the 'q' query parameter directly into the HTML body."""

    def do_GET(self):
        from urllib.parse import urlparse, parse_qs
        qs = parse_qs(urlparse(self.path).query)
        q = qs.get("q", [""])[0]
        body = f"<html><body><h1>Results for: {q}</h1></body></html>".encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format, *args):
        pass


@pytest.mark.asyncio
async def test_html_injection_no_finding_for_unrelated_script_tag():
    server = _run_server(_PlainPageHandler)
    try:
        target_url = f"http://127.0.0.1:{server.server_port}"
        endpoints = [{"path": "/search", "method": "GET", "details": {}}]
        rule = HTMLInjectionRule()
        findings = await rule.run(target_url, endpoints, {})
        assert findings == []
    finally:
        server.shutdown()


@pytest.mark.asyncio
async def test_html_injection_flags_actual_reflection():
    server = _run_server(_ReflectingPageHandler)
    try:
        target_url = f"http://127.0.0.1:{server.server_port}"
        endpoints = [{"path": "/search", "method": "GET", "details": {}}]
        rule = HTMLInjectionRule()
        findings = await rule.run(target_url, endpoints, {})
        assert len(findings) >= 1
        assert findings[0]["rule_id"] == "HTML-INJ-001"
    finally:
        server.shutdown()


class _EmailHandler(BaseHTTPRequestHandler):
    BODY = b'{"contact": "support@example.com", "owner": "jane.smith@realcorp.io"}'

    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(self.BODY)))
        self.end_headers()
        self.wfile.write(self.BODY)

    def log_message(self, format, *args):
        pass


class _PlaceholderOnlyEmailHandler(BaseHTTPRequestHandler):
    BODY = b'{"contact": "support@example.com"}'

    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(self.BODY)))
        self.end_headers()
        self.wfile.write(self.BODY)

    def log_message(self, format, *args):
        pass


@pytest.mark.asyncio
async def test_sensitive_data_ignores_placeholder_email_only():
    server = _run_server(_PlaceholderOnlyEmailHandler)
    try:
        target_url = f"http://127.0.0.1:{server.server_port}"
        endpoints = [{"path": "/info", "method": "GET", "details": {}}]
        rule = SensitiveDataRule()
        findings = await rule.run(target_url, endpoints, {})
        assert findings == []
    finally:
        server.shutdown()


@pytest.mark.asyncio
async def test_sensitive_data_flags_real_email():
    server = _run_server(_EmailHandler)
    try:
        target_url = f"http://127.0.0.1:{server.server_port}"
        endpoints = [{"path": "/info", "method": "GET", "details": {}}]
        rule = SensitiveDataRule()
        findings = await rule.run(target_url, endpoints, {})
        assert any(f["rule_id"] == "SENSITIVE-DATA" for f in findings)
    finally:
        server.shutdown()


class _FalseMarkerHandler(BaseHTTPRequestHandler):
    """Response text coincidentally contains a single weak marker substring
    ('bin:' inside 'Robin:') unrelated to any real file read."""

    def do_GET(self):
        body = b'{"assignee": "Robin: task owner"}'
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format, *args):
        pass


class _RealPasswdHandler(BaseHTTPRequestHandler):
    BODY = (
        b"root:x:0:0:root:/root:/bin/bash\n"
        b"daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
    )

    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(self.BODY)))
        self.end_headers()
        self.wfile.write(self.BODY)

    def log_message(self, format, *args):
        pass


@pytest.mark.asyncio
async def test_path_traversal_ignores_single_weak_marker():
    server = _run_server(_FalseMarkerHandler)
    try:
        target_url = f"http://127.0.0.1:{server.server_port}"
        endpoints = [{"path": "/file", "method": "GET", "details": {}}]
        rule = PathTraversalRule()
        findings = await rule.run(target_url, endpoints, {})
        assert findings == []
    finally:
        server.shutdown()


@pytest.mark.asyncio
async def test_path_traversal_flags_real_passwd_content():
    server = _run_server(_RealPasswdHandler)
    try:
        target_url = f"http://127.0.0.1:{server.server_port}"
        endpoints = [{"path": "/file", "method": "GET", "details": {}}]
        rule = PathTraversalRule()
        findings = await rule.run(target_url, endpoints, {})
        assert len(findings) >= 1
        assert findings[0]["rule_id"] == "PATH-TRAV-001"
        assert findings[0]["confidence"] == "high"
    finally:
        server.shutdown()
