import httpx
from typing import List, Dict

from app.scanner.rules.base import BaseRule


class TLSEnforcementRule(BaseRule):
    id = "TLS-ENFORCE"
    name = "TLS Enforcement Check"
    description = "Checks whether the API is served over HTTPS or redirects HTTP to HTTPS."
    severity = "medium"

    impact = "Plain HTTP allows credential/token interception and traffic manipulation."
    remediation = "Serve the API over HTTPS and redirect all HTTP traffic to HTTPS."
    cvss_vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"
    confidentiality = "High"
    integrity = "High"
    availability = "None"

    async def run(self, target_url: str, endpoints: List[Dict], config: Dict) -> List[Dict]:
        base_url = target_url.rstrip("/")
        lower = base_url.lower()

        if lower.startswith("https://"):
            return []

        if not lower.startswith("http://"):
            return []

        headers = {}
        if config.get("auth_header"):
            headers["Authorization"] = config["auth_header"]

        try:
            async with httpx.AsyncClient(verify=False, timeout=8.0, follow_redirects=False, headers=headers) as client:
                resp = await client.get(base_url)
        except Exception:
            return []

        location = resp.headers.get("location", "")
        redirects_to_https = location.lower().startswith("https://")

        if redirects_to_https:
            return [
                self.build_finding(
                    description="API is reachable over HTTP and redirects to HTTPS.",
                    details={
                        "status_code": resp.status_code,
                        "location": location,
                        "recommendation": "Prefer scanning and using the HTTPS base URL directly.",
                    },
                    endpoint="/",
                    method="GET",
                    severity="low",
                    proof_of_concept=f"GET {base_url}\nStatus: {resp.status_code}\nLocation: {location}",
                )
            ]

        return [
            self.build_finding(
                description="API appears to be served over HTTP without an HTTPS redirect.",
                details={
                    "status_code": resp.status_code,
                    "location": location or None,
                    "risk": "Traffic may be intercepted or modified in transit.",
                },
                endpoint="/",
                method="GET",
                severity="medium",
                proof_of_concept=f"GET {base_url}\nStatus: {resp.status_code}\nLocation: {location or '<none>'}",
            )
        ]
