import httpx
from typing import List, Dict
from app.scanner.rules.base import BaseRule

class FuzzingRule(BaseRule):
    id = "FUZZING"
    name = "Fuzzing-based Input Robustness"
    description = "Sends fuzzed query parameters and bodies to detect crashes and 5xx errors."
    severity = "medium"
    impact = "Unvalidated input may cause crashes or expose internal error details."
    remediation = "Validate and sanitize all inputs. Handle unexpected input types gracefully."
    cvss_vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L"
    confidentiality = "Low"
    integrity = "Low"
    availability = "Low"

    async def run(self, target_url: str, endpoints: List[Dict], config: Dict) -> List[Dict]:
        findings = []
        fuzz_values = [
            "A" * 512,
            "' OR '1'='1",
            "<script>alert(1)</script>",
            "../../etc/passwd",
            "\x00\x00\x00\x00",
            "🔥💥 fuzz 💥🔥",
        ]

        headers = {}
        if config.get("auth_header"):
            headers["Authorization"] = config["auth_header"]

        async with httpx.AsyncClient(verify=False, headers=headers) as client:
            for endpoint in endpoints:
                path = endpoint["path"]
                method = endpoint["method"].upper()
                url = f"{target_url}{path}"

                if method == "GET":
                    for value in fuzz_values:
                        try:
                            resp = await client.get(url, params={"q": value})
                            if resp.status_code >= 500:
                                findings.append(
                                    self.build_finding(
                                        description="Endpoint returned 5xx error for fuzzed query parameter.",
                                        details={
                                            "status": resp.status_code,
                                            "payload": value,
                                            "owasp": "API8: Security Misconfiguration",
                                        },
                                        endpoint=path,
                                        method="GET",
                                        severity="medium",
                                    )
                                )
                                break
                        except:
                            continue

                if method == "POST":
                    for value in fuzz_values:
                        body = {"fuzz": value}
                        try:
                            resp = await client.post(url, json=body)
                            if resp.status_code >= 500:
                                findings.append(
                                    self.build_finding(
                                        description="Endpoint returned 5xx error for fuzzed JSON body.",
                                        details={
                                            "status": resp.status_code,
                                            "payload": body,
                                            "owasp": "API8: Security Misconfiguration",
                                        },
                                        endpoint=path,
                                        method="POST",
                                        severity="medium",
                                    )
                                )
                                break
                        except:
                            continue

        return findings

