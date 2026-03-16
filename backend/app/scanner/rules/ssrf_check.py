from typing import List, Dict
import httpx
from app.scanner.rules.base import BaseRule


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

# Response patterns that suggest the server actually tried to connect
SSRF_INDICATORS = [
    "connection refused",
    "no route to host",
    "network unreachable",
    "connection timed out",
    "ami-id",           # AWS metadata response
    "instance-id",
    "local-ipv4",
    "169.254",
    "metadata",
    "root:",            # /etc/passwd fragments sometimes appear
]

QUERY_PARAM_NAMES = ["url", "target", "dest", "redirect", "uri", "path", "src", "source"]


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

    async def run(self, target_url: str, endpoints: List[Dict], config: Dict) -> List[Dict]:
        findings = []

        # Prioritise endpoints whose paths suggest URL-handling behaviour
        ssrf_candidates = [
            ep for ep in endpoints
            if any(kw in ep.get("path", "").lower() for kw in SSRF_PATH_KEYWORDS)
        ]
        # Fall back to all endpoints if no obvious candidates
        if not ssrf_candidates:
            ssrf_candidates = endpoints

        async with httpx.AsyncClient(verify=False, timeout=8.0) as client:
            for ep in ssrf_candidates:
                path = ep.get("path", "/")
                method = ep.get("method", "GET").upper()
                url = f"{target_url.rstrip('/')}{path}"

                for payload in SSRF_PAYLOADS:
                    # --- Via query parameters ---
                    for param in QUERY_PARAM_NAMES:
                        try:
                            resp = await client.get(url, params={param: payload})
                            body = resp.text.lower()

                            triggered = False
                            matched_indicator = None
                            # A 200 with substantial body from an internal URL is suspicious
                            if resp.status_code == 200 and len(resp.content) > 50:
                                triggered = True
                            # Error messages that indicate an outbound connection was attempted
                            for indicator in SSRF_INDICATORS:
                                if indicator in body:
                                    triggered = True
                                    matched_indicator = indicator
                                    break

                            if triggered:
                                findings.append(self.build_finding(
                                    description="Potential SSRF via query parameter.",
                                    details=(
                                        f"The endpoint may have issued an outbound request to "
                                        f"'{payload}' when supplied via the '{param}' query "
                                        f"parameter. "
                                        f"URL: {url}, HTTP status: {resp.status_code}"
                                        + (
                                            f", Response contained indicator: '{matched_indicator}'"
                                            if matched_indicator else ""
                                        )
                                    ),
                                    endpoint=path,
                                    method="GET",
                                    proof_of_concept=(
                                        f"GET {url}?{param}={payload}\n"
                                        f"Response: HTTP {resp.status_code} "
                                        f"({len(resp.content)} bytes)"
                                    ),
                                ))
                                break  # one finding per payload per endpoint
                        except Exception:
                            pass

                    # --- Via request body for POST/PUT/PATCH ---
                    if method in ("POST", "PUT", "PATCH"):
                        for param in QUERY_PARAM_NAMES:
                            try:
                                resp = await client.request(
                                    method,
                                    url,
                                    json={param: payload},
                                )
                                body = resp.text.lower()

                                triggered = False
                                matched_indicator = None
                                if resp.status_code == 200 and len(resp.content) > 50:
                                    triggered = True
                                for indicator in SSRF_INDICATORS:
                                    if indicator in body:
                                        triggered = True
                                        matched_indicator = indicator
                                        break

                                if triggered:
                                    findings.append(self.build_finding(
                                        description="Potential SSRF via request body parameter.",
                                        details=(
                                            f"The endpoint may have issued an outbound request to "
                                            f"'{payload}' when supplied in the '{param}' body field. "
                                            f"URL: {url}, Method: {method}, "
                                            f"HTTP status: {resp.status_code}"
                                            + (
                                                f", Response indicator: '{matched_indicator}'"
                                                if matched_indicator else ""
                                            )
                                        ),
                                        endpoint=path,
                                        method=method,
                                        proof_of_concept=(
                                            f"{method} {url}\n"
                                            f"Body: {{\"{param}\": \"{payload}\"}}\n"
                                            f"Response: HTTP {resp.status_code} "
                                            f"({len(resp.content)} bytes)"
                                        ),
                                    ))
                                    break
                            except Exception:
                                pass

        return findings
