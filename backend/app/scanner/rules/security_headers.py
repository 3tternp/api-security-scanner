import httpx
import json
from typing import List, Dict
from app.scanner.rules.base import BaseRule

class SecurityHeadersRule(BaseRule):
    id = "SEC-HEADERS"
    name = "Security Headers Check"
    description = "Checks for missing security headers and CORS misconfigurations."
    severity = "medium"

    impact = "Attackers may exploit missing headers to perform clickjacking, MIME sniffing, or XSS attacks."
    remediation = "Configure the web server to send standard security headers (X-Content-Type-Options, X-Frame-Options, CSP)."
    cvss_vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N"
    confidentiality = "Low"
    integrity = "Low"
    availability = "None"

    async def run(self, target_url: str, endpoints: List[Dict], config: Dict, baseline_cache=None) -> List[Dict]:
        findings = []
        try:
            async with httpx.AsyncClient(verify=False) as client:
                response = await client.get(target_url)
                headers = response.headers

                csp = headers.get("Content-Security-Policy", "")
                has_frame_ancestors = "frame-ancestors" in csp.lower()

                missing_headers = []
                required_headers = [
                    "X-Content-Type-Options",
                    "X-Frame-Options",
                    "Content-Security-Policy"
                ]

                for h in required_headers:
                    if h in headers:
                        continue
                    # CSP frame-ancestors is the modern replacement for
                    # X-Frame-Options and is required for apps that must be
                    # embeddable (e.g. a Salesforce Canvas iframe app) —
                    # don't flag framing protection as missing twice when
                    # the app has deliberately chosen the CSP mechanism.
                    if h == "X-Frame-Options" and has_frame_ancestors:
                        continue
                    missing_headers.append(h)

                if missing_headers:
                    findings.append(self.build_finding(
                        description=f"Missing security headers: {', '.join(missing_headers)}",
                        details={
                            "explanation": f"The application is missing the following security headers: {', '.join(missing_headers)}. This can leave it vulnerable to various attacks.",
                            "owasp": "API8: Security Misconfiguration"
                        },
                        proof_of_concept=f"Response Headers:\n{json.dumps(dict(headers), indent=2)}",
                        endpoint="/",
                        method="GET",
                        severity="low"
                    ))

                if "Access-Control-Allow-Origin" in headers:
                    if headers["Access-Control-Allow-Origin"] == "*":
                         findings.append(self.build_finding(
                            description="CORS Access-Control-Allow-Origin is set to wildcard (*)",
                            details={
                                "explanation": "The Access-Control-Allow-Origin header is set to *, allowing any domain to access resources.",
                                "owasp": "API8: Security Misconfiguration"
                            },
                            proof_of_concept=f"Response Headers:\n{json.dumps(dict(headers), indent=2)}",
                            endpoint="/",
                            method="GET",
                            severity="medium"
                        ))

        except Exception as e:
            pass # Handle errors gracefully
            
        return findings
