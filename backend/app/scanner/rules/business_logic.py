import httpx
from typing import List, Dict
from app.scanner.rules.base import BaseRule

class BusinessLogicRule(BaseRule):
    id = "BUSINESS-LOGIC"
    name = "Sensitive Business Flow Checks"
    description = "Looks for unrestricted access to sensitive business flows by repeating POST operations."
    severity = "medium"
    impact = "Critical business actions may be repeated without proper safeguards."
    remediation = "Enforce business rules such as idempotency keys, step validation, and replay protection."
    cvss_vector = "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:H/A:L"
    confidentiality = "Low"
    integrity = "High"
    availability = "Low"

    async def run(self, target_url: str, endpoints: List[Dict], config: Dict) -> List[Dict]:
        findings = []
        keywords = [
            "transfer",
            "payment",
            "checkout",
            "order",
            "purchase",
            "withdraw",
            "deposit",
        ]

        headers = {}
        if config.get("auth_header"):
            headers["Authorization"] = config["auth_header"]

        async with httpx.AsyncClient(verify=False, headers=headers) as client:
            for endpoint in endpoints:
                method = endpoint["method"].upper()
                path = endpoint["path"]
                lower_path = path.lower()

                if method != "POST":
                    continue

                if not any(k in lower_path for k in keywords):
                    continue

                url = f"{target_url}{path}"
                payload = {"action": "test", "amount": 1}
                statuses = []

                try:
                    for _ in range(3):
                        resp = await client.post(url, json=payload)
                        statuses.append(resp.status_code)
                except:
                    continue

                if all(200 <= s < 300 for s in statuses):
                    findings.append(
                        self.build_finding(
                            description="POST endpoint for sensitive business flow accepted repeated requests.",
                            details={
                                "statuses": statuses,
                                "path": path,
                                "owasp": "API6: Unrestricted Access to Sensitive Business Flows",
                            },
                            endpoint=path,
                            method="POST",
                            severity="medium",
                        )
                    )

        return findings

