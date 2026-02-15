import httpx
import re
from typing import List, Dict
from app.scanner.rules.base import BaseRule

class DeserializationRule(BaseRule):
    id = "DESERIALIZATION"
    name = "Unsafe Deserialization Indicators"
    description = "Looks for error messages and stack traces that indicate unsafe deserialization."
    severity = "medium"
    impact = "Error pages and stack traces may reveal unsafe deserialization sinks."
    remediation = "Harden deserialization logic, avoid unsafe deserializers, and disable detailed error pages."
    cvss_vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N"
    confidentiality = "Low"
    integrity = "Low"

    async def run(self, target_url: str, endpoints: List[Dict], config: Dict) -> List[Dict]:
        findings = []
        patterns = [
            r"java\.io\.ObjectInputStream",
            r"ObjectInputStream\.readObject",
            r"org\.apache\.commons\.collections",
            r"BinaryFormatter\.Deserialize",
            r"System\.Runtime\.Serialization",
            r"pickle\.loads",
            r"yaml\.load\(",
            r"gson\.fromJson",
        ]
        combined = re.compile("|".join(patterns), re.IGNORECASE)

        headers = {}
        if config.get("auth_header"):
            headers["Authorization"] = config["auth_header"]

        async with httpx.AsyncClient(verify=False, headers=headers) as client:
            for endpoint in endpoints:
                if endpoint["method"] != "GET":
                    continue
                url = f"{target_url}{endpoint['path']}"
                try:
                    resp = await client.get(url)
                    text = resp.text
                    if combined.search(text):
                        findings.append(
                            self.build_finding(
                                description="Potential unsafe deserialization indicators found in response content.",
                                details={
                                    "status": resp.status_code,
                                    "snippet": text[:500],
                                    "owasp": "API8: Security Misconfiguration",
                                },
                                endpoint=endpoint["path"],
                                method="GET",
                                severity="medium",
                            )
                        )
                except:
                    continue

        return findings

