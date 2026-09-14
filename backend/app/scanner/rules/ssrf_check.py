from typing import List, Dict, Optional, Tuple
import time
import httpx
from app.scanner.rules.base import BaseRule, bounded_gather
from app.scanner.allowlists import SSRF_METADATA_MARKERS


SSRF_PATH_KEYWORDS = [
    "/fetch", "/proxy", "/redirect", "/url", "/webhook",
    "/callback", "/load", "/download", "/import", "/request",
]

SSRF_PAYLOADS = [
    "http://127.0.0.1",
    "http://localhost:80",
    "http://169.254.169.254",           # AWS metadata
    "http://169.254.169.254/latest/meta-data/",
    "http://[::1]",                      # IPv6 loopback
    "http://0.0.0.0",
]

# Error messages that indicate the server actually attempted an outbound
# connection (as opposed to just reflecting the payload back or ignoring it).
CONNECTION_ATTEMPT_INDICATORS = [
    "connection refused",
    "no route to host",
    "network unreachable",
    "connection timed out",
]

QUERY_PARAM_NAMES = ["url", "target", "dest", "redirect", "uri", "path", "src", "source"]

# A probe response taking this many times longer than baseline (and at least
# this many ms) suggests the server actually tried to open a connection to
# the internal host rather than instantly reflecting/ignoring the payload.
TIMING_ANOMALY_RATIO = 3.0
TIMING_ANOMALY_MIN_MS = 500


class SSRFCheckRule(BaseRule):
    id = "SSRF-001"
    name = "Server-Side Request Forgery (SSRF)"
    severity = "high"
    impact = (
        "An attacker can make the server issue requests to internal services, "
        "cloud metadata endpoints, or other hosts not accessible from the internet, "
        "potentially exposing credentials, configuration, and internal infrastructure."
    )
    remediation = (
        "Validate and sanitize all user-supplied URLs. Use an allowlist of permitted "
        "destinations. Block requests to private IP ranges (RFC 1918, link-local) "
        "and cloud metadata endpoints at the network layer."
    )
    cvss_vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N"
    attack_vector = "Network"
    attack_complexity = "Low"
    privileges_required = "None"
    user_interaction = "None"
    scope = "Changed"
    confidentiality = "High"
    integrity = "None"
    availability = "None"

    def _evaluate(self, elapsed_ms: float, baseline_ms: float, body: str):
        """Return (triggered, signals, matched_indicator) for a probe response."""
        signals = []
        matched_indicator = None

        for marker in SSRF_METADATA_MARKERS:
            if marker in body:
                signals.append("metadata_marker_found")
                matched_indicator = marker
                break

        for indicator in CONNECTION_ATTEMPT_INDICATORS:
            if indicator in body:
                signals.append("connection_attempt_error")
                matched_indicator = matched_indicator or indicator
                break

        if baseline_ms and elapsed_ms >= max(baseline_ms * TIMING_ANOMALY_RATIO, TIMING_ANOMALY_MIN_MS):
            signals.append("timing_anomaly")

        # Timing alone is too noisy to trust as sole evidence: probes run
        # concurrently (bounded_gather), so queueing delay from the burst of
        # in-flight requests can slow a probe relative to the single
        # sequential baseline measurement, independent of whether the server
        # actually made an outbound connection. Require a body-based
        # indicator (metadata marker or connection error) to actually trigger
        # a finding — timing only ever corroborates one of those.
        has_body_signal = "metadata_marker_found" in signals or "connection_attempt_error" in signals
        return (has_body_signal, signals, matched_indicator)

    async def _probe_query(self, client, target_url, ep, payload, param, baseline_ms) -> Optional[Tuple[Dict, str]]:
        path = ep.get("path", "/")
        url = f"{target_url.rstrip('/')}{path}"
        try:
            t0 = time.monotonic()
            resp = await client.get(url, params={param: payload})
            elapsed_ms = (time.monotonic() - t0) * 1000
            body = resp.text.lower()

            triggered, signals, matched_indicator = self._evaluate(elapsed_ms, baseline_ms, body)
            if not triggered:
                return None
            finding = self.build_finding(
                description="Potential SSRF via query parameter.",
                details=(
                    f"The endpoint may have issued an outbound request to "
                    f"'{payload}' when supplied via the '{param}' query "
                    f"parameter. "
                    f"URL: {url}, HTTP status: {resp.status_code}"
                    + (
                        f", indicator: '{matched_indicator}'"
                        if matched_indicator else ""
                    )
                    + f", signals: {signals}"
                ),
                endpoint=path,
                method="GET",
                proof_of_concept=(
                    f"GET {url}?{param}={payload}\n"
                    f"Response: HTTP {resp.status_code} "
                    f"({elapsed_ms:.0f}ms vs baseline {baseline_ms:.0f}ms)"
                ),
                signals=signals,
            )
            return finding, payload  # tag with payload so we can dedupe to one-per-payload
        except Exception:
            return None

    async def _probe_body(self, client, target_url, ep, payload, param, baseline_ms) -> Optional[Tuple[Dict, str]]:
        path = ep.get("path", "/")
        method = ep.get("method", "GET").upper()
        url = f"{target_url.rstrip('/')}{path}"
        try:
            t0 = time.monotonic()
            resp = await client.request(method, url, json={param: payload})
            elapsed_ms = (time.monotonic() - t0) * 1000
            body = resp.text.lower()

            triggered, signals, matched_indicator = self._evaluate(elapsed_ms, baseline_ms, body)
            if not triggered:
                return None
            finding = self.build_finding(
                description="Potential SSRF via request body parameter.",
                details=(
                    f"The endpoint may have issued an outbound request to "
                    f"'{payload}' when supplied in the '{param}' body field. "
                    f"URL: {url}, Method: {method}, "
                    f"HTTP status: {resp.status_code}"
                    + (
                        f", indicator: '{matched_indicator}'"
                        if matched_indicator else ""
                    )
                    + f", signals: {signals}"
                ),
                endpoint=path,
                method=method,
                proof_of_concept=(
                    f"{method} {url}\n"
                    f"Body: {{\"{param}\": \"{payload}\"}}\n"
                    f"Response: HTTP {resp.status_code} "
                    f"({elapsed_ms:.0f}ms vs baseline {baseline_ms:.0f}ms)"
                ),
                signals=signals,
            )
            return finding, payload
        except Exception:
            return None

    async def run(self, target_url: str, endpoints: List[Dict], config: Dict, baseline_cache=None) -> List[Dict]:
        findings = []

        ssrf_candidates = [
            ep for ep in endpoints
            if any(kw in ep.get("path", "").lower() for kw in SSRF_PATH_KEYWORDS)
        ]
        if not ssrf_candidates:
            ssrf_candidates = endpoints

        headers = {}
        if config.get('auth_header'):
            headers['Authorization'] = config['auth_header']

        async with httpx.AsyncClient(verify=False, timeout=8.0, headers=headers) as client:
            # Baseline timing per endpoint first (one request each, sequential —
            # cheap relative to the full payload x param sweep below).
            baseline_ms_by_path: Dict[str, float] = {}
            for ep in ssrf_candidates:
                path = ep.get("path", "/")
                url = f"{target_url.rstrip('/')}{path}"
                baseline_ms = 0.0
                try:
                    t0 = time.monotonic()
                    await client.get(url, params={QUERY_PARAM_NAMES[0]: "https://example.com"})
                    baseline_ms = (time.monotonic() - t0) * 1000
                except Exception:
                    pass
                baseline_ms_by_path[path] = baseline_ms

            # Build every (endpoint, payload, param) probe as a task and run them
            # concurrently (bounded) instead of one at a time — this loop used to
            # be fully sequential and could mean thousands of serial round-trips
            # on a spec with many endpoints.
            tasks = []
            for ep in ssrf_candidates:
                path = ep.get("path", "/")
                method = ep.get("method", "GET").upper()
                baseline_ms = baseline_ms_by_path.get(path, 0.0)
                for payload in SSRF_PAYLOADS:
                    for param in QUERY_PARAM_NAMES:
                        tasks.append(self._probe_query(client, target_url, ep, payload, param, baseline_ms))
                    if method in ("POST", "PUT", "PATCH"):
                        for param in QUERY_PARAM_NAMES:
                            tasks.append(self._probe_body(client, target_url, ep, payload, param, baseline_ms))

            results = await bounded_gather(tasks, limit=15)

            seen = set()  # (endpoint, method, payload) -> keep only first match, same as old "break"
            for r in results:
                if not r or isinstance(r, Exception):
                    continue
                finding, payload = r
                key = (finding["endpoint"], finding["method"], payload)
                if key in seen:
                    continue
                seen.add(key)
                findings.append(finding)

        return findings
