from typing import List, Dict
import httpx
from app.scanner.rules.base import BaseRule
from app.scanner.signals import is_html_context


class HTMLInjectionRule(BaseRule):
    id = "HTML-INJ-001"
    name = "HTML / Template Injection"
    severity = "medium"
    impact = (
        "Reflected HTML can be used to perform phishing attacks, deface pages, "
        "or escalate to stored XSS if the response is cached or persisted."
    )
    remediation = (
        "HTML-encode all user-supplied input before rendering it in responses. "
        "Use a Content Security Policy (CSP) to limit script execution."
    )
    cvss_vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"
    attack_vector = "Network"
    attack_complexity = "Low"
    privileges_required = "None"
    user_interaction = "Required"
    scope = "Changed"
    confidentiality = "Low"
    integrity = "Low"
    availability = "None"

    PAYLOADS = [
        "<h1>test</h1>",
        "<script>alert(1)</script>",
        "<img src=x onerror=alert(1)>",
        "<svg/onload=alert(1)>",
    ]
    PARAM_NAMES = ["q", "search", "name", "input"]

    async def run(self, target_url: str, endpoints: List[Dict], config: Dict, baseline_cache=None) -> List[Dict]:
        findings = []
        test_endpoints = endpoints[:5]

        headers = {}
        if config.get('auth_header'):
            headers['Authorization'] = config['auth_header']

        async with httpx.AsyncClient(verify=False, timeout=8.0, headers=headers) as client:
            for ep in test_endpoints:
                path = ep.get("path", "/")
                method = ep.get("method", "GET").upper()
                url = f"{target_url.rstrip('/')}{path}"

                baseline = await baseline_cache.get(client, "GET", path) if baseline_cache else None
                baseline_text = (baseline.body if baseline else "").lower()

                for payload in self.PAYLOADS:
                    payload_lower = payload.lower()

                    # Test via query parameters
                    for param in self.PARAM_NAMES:
                        try:
                            resp = await client.get(url, params={param: payload})
                            body = resp.text
                            content_type = resp.headers.get("content-type", "")
                            # Only a browser-rendered HTML response can actually
                            # execute the reflected markup — a JSON API echoing
                            # the same raw string back isn't exploitable here.
                            if not is_html_context(content_type):
                                continue
                            # Check for THIS payload specifically, not just any
                            # marker drawn from the whole payload set — matching
                            # "<script>" just because a real page's own bundled
                            # JS happens to contain a <script> tag (true of
                            # almost every HTML page) is not a reflection of
                            # what we sent.
                            if payload_lower in body.lower() and payload_lower not in baseline_text:
                                findings.append(self.build_finding(
                                    description="HTML injection payload reflected in response.",
                                    details=(
                                        f"The payload '{payload}' sent as query parameter "
                                        f"'{param}' was reflected verbatim in the response "
                                        f"body without encoding. URL: {url}"
                                    ),
                                    endpoint=path,
                                    method="GET",
                                    proof_of_concept=(
                                        f"GET {url}?{param}={payload}\n"
                                        f"Response contained: {payload}"
                                    ),
                                    signals=["payload_reflected_verbatim", "html_content_type", "absent_on_baseline"],
                                ))
                                break  # one finding per param/payload combo
                        except Exception:
                            pass

                    # Test via request body for POST/PUT/PATCH
                    if method in ("POST", "PUT", "PATCH"):
                        for param in self.PARAM_NAMES:
                            try:
                                resp = await client.request(
                                    method,
                                    url,
                                    json={param: payload},
                                )
                                body = resp.text
                                content_type = resp.headers.get("content-type", "")
                                if not is_html_context(content_type):
                                    continue
                                if payload_lower in body.lower() and payload_lower not in baseline_text:
                                    findings.append(self.build_finding(
                                        description="HTML injection payload reflected in response body.",
                                        details=(
                                            f"The payload '{payload}' sent in the request body "
                                            f"field '{param}' was reflected verbatim in the "
                                            f"response without encoding. URL: {url}, Method: {method}"
                                        ),
                                        endpoint=path,
                                        method=method,
                                        proof_of_concept=(
                                            f"{method} {url}\n"
                                            f"Body: {{\"{param}\": \"{payload}\"}}\n"
                                            f"Response contained: {payload}"
                                        ),
                                        signals=["payload_reflected_verbatim", "html_content_type", "absent_on_baseline"],
                                    ))
                                    break
                            except Exception:
                                pass

        return findings
