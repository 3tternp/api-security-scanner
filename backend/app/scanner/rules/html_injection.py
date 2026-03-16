from typing import List, Dict
import httpx
from app.scanner.rules.base import BaseRule


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
    # Markers we look for in the response body (raw tags reflected back)
    REFLECTION_MARKERS = ["<h1>", "<script>", "<img ", "<svg"]

    async def run(self, target_url: str, endpoints: List[Dict], config: Dict) -> List[Dict]:
        findings = []
        test_endpoints = endpoints[:5]

        async with httpx.AsyncClient(verify=False, timeout=8.0) as client:
            for ep in test_endpoints:
                path = ep.get("path", "/")
                method = ep.get("method", "GET").upper()
                url = f"{target_url.rstrip('/')}{path}"

                for payload in self.PAYLOADS:
                    # Test via query parameters
                    for param in self.PARAM_NAMES:
                        try:
                            resp = await client.get(url, params={param: payload})
                            body = resp.text
                            for marker in self.REFLECTION_MARKERS:
                                if marker.lower() in body.lower():
                                    findings.append(self.build_finding(
                                        description="HTML injection payload reflected in response.",
                                        details=(
                                            f"The payload '{payload}' sent as query parameter "
                                            f"'{param}' was reflected in the response body "
                                            f"without encoding. URL: {url}"
                                        ),
                                        endpoint=path,
                                        method="GET",
                                        proof_of_concept=(
                                            f"GET {url}?{param}={payload}\n"
                                            f"Response contained: {marker}"
                                        ),
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
                                for marker in self.REFLECTION_MARKERS:
                                    if marker.lower() in body.lower():
                                        findings.append(self.build_finding(
                                            description="HTML injection payload reflected in response body.",
                                            details=(
                                                f"The payload '{payload}' sent in the request body "
                                                f"field '{param}' was reflected in the response "
                                                f"without encoding. URL: {url}, Method: {method}"
                                            ),
                                            endpoint=path,
                                            method=method,
                                            proof_of_concept=(
                                                f"{method} {url}\n"
                                                f"Body: {{\"{param}\": \"{payload}\"}}\n"
                                                f"Response contained: {marker}"
                                            ),
                                        ))
                                        break
                            except Exception:
                                pass

        return findings
