import httpx
from typing import List, Dict
from app.scanner.rules.base import BaseRule
from app.scanner.allowlists import is_public_path

GARBAGE_TOKEN = "Bearer not-a-real-token-abc123"


class AuthRequiredRule(BaseRule):
    id = "AUTH-MISSING"
    name = "Authentication Missing Check"
    description = "Checks if sensitive endpoints are accessible without authentication."
    severity = "high"

    impact = "Unauthorized access to sensitive data or functionality."
    remediation = "Implement authentication middleware (e.g., JWT, OAuth2, API Keys) for all private endpoints. Verify that the API rejects unauthenticated requests with 401 Unauthorized."
    cvss_vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    confidentiality = "High"
    integrity = "High"
    availability = "High"

    async def run(self, target_url: str, endpoints: List[Dict], config: Dict, baseline_cache=None) -> List[Dict]:
        findings = []
        async with httpx.AsyncClient(verify=False, timeout=8.0) as client:
            for endpoint in endpoints:
                path = endpoint['path']
                method = endpoint['method']

                # Skip conventionally-public endpoints (login, health checks, docs, etc.)
                if is_public_path(path):
                    continue

                if method.upper() not in ("GET", "POST"):
                    continue

                full_url = f"{target_url}{path}"

                try:
                    if method.upper() == "GET":
                        response = await client.get(full_url)
                    else:
                        response = await client.post(full_url, json={})
                except Exception:
                    continue

                if response.status_code != 200:
                    continue

                signals = ["unauthenticated_2xx", "path_not_publicly_named"]

                # Control: does a bogus/garbage token get rejected? If the server
                # rejects an invalid token while accepting no token at all, that's
                # a strong confirmation auth is genuinely broken (not just absent
                # by design for a public endpoint).
                try:
                    if method.upper() == "GET":
                        control_resp = await client.get(full_url, headers={"Authorization": GARBAGE_TOKEN})
                    else:
                        control_resp = await client.post(full_url, json={}, headers={"Authorization": GARBAGE_TOKEN})
                    if control_resp.status_code in (401, 403):
                        signals.append("garbage_token_rejected")
                except Exception:
                    pass

                findings.append(self.build_finding(
                    description=f"Endpoint {method} {path} is accessible without authentication.",
                    details={
                        "status": response.status_code,
                        "body": str(response.text)[:200],
                        "owasp": "API2: Broken Authentication",
                        "signals": signals,
                    },
                    endpoint=path,
                    method=method,
                    signals=signals,
                ))

        return findings
