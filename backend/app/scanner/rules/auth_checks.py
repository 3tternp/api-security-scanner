import httpx
from typing import List, Dict
from app.scanner.rules.base import BaseRule

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

    async def run(self, target_url: str, endpoints: List[Dict], config: Dict) -> List[Dict]:
        findings = []
        async with httpx.AsyncClient(verify=False) as client:
            for endpoint in endpoints:
                path = endpoint['path']
                method = endpoint['method']
                
                # Skip login/public endpoints usually
                if "login" in path or "public" in path:
                    continue
                
                full_url = f"{target_url}{path}"
                
                try:
                    # Send request without headers
                    if method.upper() == "GET":
                        response = await client.get(full_url)
                    elif method.upper() == "POST":
                        response = await client.post(full_url, json={})
                    else:
                        continue # Skip other methods for now

                    if response.status_code == 200:
                        findings.append(self.build_finding(
                            description=f"Endpoint {method} {path} is accessible without authentication.",
                            details={
                                "status": response.status_code,
                                "body": str(response.text)[:200],
                                "owasp": "API2: Broken Authentication"
                            },
                            endpoint=path,
                            method=method
                        ))
                except Exception:
                    continue
                    
        return findings
