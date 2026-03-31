import httpx
import json
from typing import List, Dict

from app.scanner.rules.base import BaseRule


class FingerprintHeadersRule(BaseRule):
    id = "FINGERPRINT"
    name = "Technology Fingerprinting Headers"
    description = "Detects response headers that may disclose server/framework information."
    severity = "low"

    impact = "Disclosing server/framework details can help attackers tailor exploits to known vulnerabilities."
    remediation = "Remove or minimize identifying headers (e.g., Server, X-Powered-By) at the edge/proxy layer."
    cvss_vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"
    confidentiality = "Low"
    integrity = "None"
    availability = "None"

    FINGERPRINT_HEADERS = [
        "server",
        "x-powered-by",
        "x-aspnet-version",
        "x-aspnetmvc-version",
        "x-generator",
        "x-runtime",
        "x-version",
        "via",
    ]

    async def run(self, target_url: str, endpoints: List[Dict], config: Dict) -> List[Dict]:
        base_url = target_url.rstrip("/")

        headers = {}
        if config.get("auth_header"):
            headers["Authorization"] = config["auth_header"]

        try:
            async with httpx.AsyncClient(verify=False, headers=headers, timeout=8.0) as client:
                resp = await client.get(base_url)
        except Exception:
            return []

        found = {}
        for h in self.FINGERPRINT_HEADERS:
            if h in resp.headers:
                found[h] = resp.headers.get(h)

        if not found:
            return []

        return [
            self.build_finding(
                description="Fingerprinting headers detected in API responses.",
                details={
                    "headers": found,
                    "status_code": resp.status_code,
                },
                endpoint="/",
                method="GET",
                severity="low",
                proof_of_concept=json.dumps(found, indent=2),
            )
        ]
