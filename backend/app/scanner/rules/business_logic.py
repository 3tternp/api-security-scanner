import httpx
from typing import List, Dict, Optional
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

    def _side_effect_id(self, resp: httpx.Response) -> Optional[str]:
        """Extract a resource/transaction identifier from a response, if any,
        to tell 'three separate side effects happened' apart from 'the same
        idempotent result was returned three times'."""
        try:
            body = resp.json()
        except Exception:
            return None
        if not isinstance(body, dict):
            return None
        for key in ("id", "_id", "transaction_id", "order_id", "uuid"):
            if key in body:
                return str(body[key])
        return None

    async def run(self, target_url: str, endpoints: List[Dict], config: Dict, baseline_cache=None) -> List[Dict]:
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
                side_effect_ids = []
                bodies = []

                try:
                    # No Idempotency-Key sent — a safe implementation should
                    # either reject repeats or return the same side effect.
                    for _ in range(3):
                        resp = await client.post(url, json=payload)
                        statuses.append(resp.status_code)
                        side_effect_ids.append(self._side_effect_id(resp))
                        bodies.append(resp.text)
                except Exception:
                    continue

                if not all(200 <= s < 300 for s in statuses):
                    continue

                signals = ["repeated_success_no_idempotency_key"]

                extracted_ids = [i for i in side_effect_ids if i is not None]
                if len(extracted_ids) == 3 and len(set(extracted_ids)) == 3:
                    # Three distinct resource/transaction IDs for the same
                    # logical action — three separate side effects occurred.
                    signals.append("distinct_resource_ids_per_repeat")
                elif not extracted_ids and len(set(bodies)) == 3:
                    # No identifier field to key off of — fall back to whether
                    # the three response bodies were all distinct.
                    signals.append("distinct_response_bodies_per_repeat")
                else:
                    # Repeats look idempotent (same id/body each time) — not a
                    # real business-logic bypass signal.
                    continue

                findings.append(
                    self.build_finding(
                        description="POST endpoint for sensitive business flow accepted repeated requests with distinct side effects and no idempotency protection.",
                        details={
                            "statuses": statuses,
                            "side_effect_ids": side_effect_ids,
                            "path": path,
                            "owasp": "API6: Unrestricted Access to Sensitive Business Flows",
                        },
                        endpoint=path,
                        method="POST",
                        severity="medium",
                        signals=signals,
                    )
                )

        return findings
