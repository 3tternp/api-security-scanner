from typing import List, Dict
import httpx
from app.scanner.rules.base import BaseRule


class CORSCheckRule(BaseRule):
    id = "CORS-001"
    name = "CORS Misconfiguration"
    severity = "high"
    impact = (
        "An attacker can make cross-origin requests on behalf of authenticated users, "
        "potentially leaking sensitive data or performing unauthorized actions."
    )
    remediation = (
        "Restrict Access-Control-Allow-Origin to a whitelist of trusted origins. "
        "Never reflect arbitrary origins. Do not combine wildcard with credentials."
    )
    cvss_vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:L/A:N"
    attack_vector = "Network"
    attack_complexity = "Low"
    privileges_required = "None"
    user_interaction = "Required"
    scope = "Unchanged"
    confidentiality = "High"
    integrity = "Low"
    availability = "None"

    TEST_ORIGINS = [
        "https://evil.com",
        "null",
        "https://attacker.com",
    ]

    async def run(self, target_url: str, endpoints: List[Dict], config: Dict) -> List[Dict]:
        findings = []
        test_endpoints = endpoints[:3]

        async with httpx.AsyncClient(verify=False, timeout=8.0) as client:
            for ep in test_endpoints:
                path = ep.get("path", "/")
                url = f"{target_url.rstrip('/')}{path}"

                for origin in self.TEST_ORIGINS:
                    for method in ["OPTIONS", "GET"]:
                        try:
                            headers = {
                                "Origin": origin,
                                "Access-Control-Request-Method": "GET",
                                "Access-Control-Request-Headers": "Authorization",
                            }
                            if method == "GET":
                                resp = await client.get(url, headers=headers)
                            else:
                                resp = await client.options(url, headers=headers)

                            acao = resp.headers.get("access-control-allow-origin", "")
                            acac = resp.headers.get("access-control-allow-credentials", "").lower()

                            # Wildcard ACAO
                            if acao == "*":
                                findings.append(self.build_finding(
                                    description="Wildcard Access-Control-Allow-Origin detected.",
                                    details=(
                                        f"The endpoint returns 'Access-Control-Allow-Origin: *', "
                                        f"allowing any origin to read responses. "
                                        f"URL: {url}, Method: {method}, Origin: {origin}"
                                    ),
                                    endpoint=path,
                                    method=method,
                                    proof_of_concept=(
                                        f"Request with Origin: {origin} returned "
                                        f"Access-Control-Allow-Origin: *"
                                    ),
                                ))
                                break  # one finding per endpoint/method is enough for wildcard

                            # Arbitrary origin reflection
                            if acao == origin and origin not in ("null",):
                                detail_parts = [
                                    f"The server reflects the supplied Origin header verbatim: '{origin}'.",
                                    f"URL: {url}, Method: {method}.",
                                ]
                                if acac == "true":
                                    detail_parts.append(
                                        "Access-Control-Allow-Credentials is also 'true', "
                                        "enabling credentialed cross-origin requests."
                                    )
                                findings.append(self.build_finding(
                                    description="Arbitrary origin reflection in CORS response.",
                                    details=" ".join(detail_parts),
                                    endpoint=path,
                                    method=method,
                                    proof_of_concept=(
                                        f"Request with Origin: {origin} returned "
                                        f"Access-Control-Allow-Origin: {acao}"
                                        + (" with credentials allowed." if acac == "true" else ".")
                                    ),
                                ))

                            # Null origin accepted
                            if origin == "null" and acao == "null":
                                findings.append(self.build_finding(
                                    description="Null origin accepted in CORS policy.",
                                    details=(
                                        f"The server accepts 'null' as a valid origin. "
                                        f"Sandboxed iframes can use the null origin to bypass CORS. "
                                        f"URL: {url}, Method: {method}."
                                    ),
                                    endpoint=path,
                                    method=method,
                                    proof_of_concept=(
                                        "Request with Origin: null returned "
                                        "Access-Control-Allow-Origin: null"
                                    ),
                                ))

                        except Exception:
                            pass

        return findings
