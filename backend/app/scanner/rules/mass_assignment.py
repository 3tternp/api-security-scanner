from typing import List, Dict
import httpx
from app.scanner.rules.base import BaseRule


SENSITIVE_FIELDS = {
    "role": "admin",
    "admin": True,
    "is_admin": True,
    "is_superuser": True,
    "permissions": ["read", "write", "admin"],
    "balance": 99999,
    "credit": 99999,
    "verified": True,
    "active": True,
    "staff": True,
    "superuser": True,
}

WRITE_METHODS = {"POST", "PUT", "PATCH"}


class MassAssignmentRule(BaseRule):
    id = "MASS-ASSIGN-001"
    name = "Mass Assignment / Over-Posting"
    severity = "high"
    impact = (
        "An attacker can set privileged fields (e.g., role, is_admin, balance) "
        "that should never be modifiable by end users, leading to privilege escalation "
        "or financial fraud."
    )
    remediation = (
        "Use explicit allowlists (DTOs / serializer schemas) that only permit expected "
        "fields. Never bind request data directly to database models. Reject or ignore "
        "unknown fields in incoming request bodies."
    )
    cvss_vector = "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N"
    attack_vector = "Network"
    attack_complexity = "Low"
    privileges_required = "Low"
    user_interaction = "None"
    scope = "Unchanged"
    confidentiality = "High"
    integrity = "High"
    availability = "None"

    async def run(self, target_url: str, endpoints: List[Dict], config: Dict) -> List[Dict]:
        findings = []

        write_endpoints = [
            ep for ep in endpoints
            if ep.get("method", "GET").upper() in WRITE_METHODS
        ]

        async with httpx.AsyncClient(verify=False, timeout=8.0) as client:
            for ep in write_endpoints:
                path = ep.get("path", "/")
                method = ep.get("method", "POST").upper()
                url = f"{target_url.rstrip('/')}{path}"

                # First make a baseline request with just a benign field
                baseline_body = {"name": "test_user", "email": "test@example.com"}
                baseline_status = None
                try:
                    baseline_resp = await client.request(method, url, json=baseline_body)
                    baseline_status = baseline_resp.status_code
                except Exception:
                    pass

                # Now inject sensitive fields alongside the baseline payload
                injected_body = dict(baseline_body)
                injected_body.update(SENSITIVE_FIELDS)

                try:
                    resp = await client.request(method, url, json=injected_body)
                    status = resp.status_code

                    # Flag if the server returns success (2xx) — it accepted the payload
                    # without rejecting the sensitive fields
                    if status in range(200, 300):
                        # Check whether any sensitive field name appears in the response
                        body_text = resp.text.lower()
                        accepted_fields = [
                            field for field in SENSITIVE_FIELDS
                            if field.lower() in body_text
                        ]

                        findings.append(self.build_finding(
                            description="Endpoint may be vulnerable to mass assignment.",
                            details=(
                                f"The endpoint accepted a request body containing sensitive "
                                f"privilege-escalation fields without returning an error. "
                                f"Injected fields: {list(SENSITIVE_FIELDS.keys())}. "
                                f"Fields reflected in response: {accepted_fields or 'none detected'}. "
                                f"URL: {url}, Method: {method}, "
                                f"HTTP status: {status}"
                                + (
                                    f" (baseline: {baseline_status})"
                                    if baseline_status else ""
                                )
                            ),
                            endpoint=path,
                            method=method,
                            proof_of_concept=(
                                f"{method} {url}\n"
                                f"Body included: {list(SENSITIVE_FIELDS.keys())}\n"
                                f"Response: HTTP {status}"
                            ),
                        ))
                except Exception:
                    pass

        return findings
