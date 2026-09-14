from typing import List, Dict, Optional
import json
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

    async def run(self, target_url: str, endpoints: List[Dict], config: Dict, baseline_cache=None) -> List[Dict]:
        findings = []

        write_endpoints = [
            ep for ep in endpoints
            if ep.get("method", "GET").upper() in WRITE_METHODS
        ]

        headers = {}
        if config.get('auth_header'):
            headers['Authorization'] = config['auth_header']

        async with httpx.AsyncClient(verify=False, timeout=8.0, headers=headers) as client:
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

                    if status not in range(200, 300):
                        continue

                    # A bare 2xx isn't proof the sensitive fields were actually
                    # stored — re-fetch the resource and confirm the *values*
                    # (not just the field names) came back.
                    fetched = await self._refetch(client, url, method, resp)
                    confirmed_fields = self._confirm_fields_applied(fetched)

                    if not confirmed_fields:
                        # Nothing confirmed applied — don't flag; a bare 2xx
                        # with no re-fetch confirmation is too weak a signal.
                        continue

                    signals = ["write_accepted_2xx", "injected_value_confirmed_on_refetch"]

                    findings.append(self.build_finding(
                        description="Endpoint is vulnerable to mass assignment.",
                        details=(
                            f"The endpoint accepted a request body containing sensitive "
                            f"privilege-escalation fields, and a re-fetch of the resource "
                            f"confirmed the injected values were actually applied. "
                            f"Confirmed fields: {confirmed_fields}. "
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
                            f"Response: HTTP {status}\n"
                            f"Re-fetch confirmed applied: {confirmed_fields}"
                        ),
                        signals=signals,
                    ))
                except Exception:
                    pass

        return findings

    async def _refetch(self, client: httpx.AsyncClient, url: str, method: str, write_resp: httpx.Response) -> Optional[dict]:
        """Re-fetch the written resource to confirm what was actually persisted."""
        try:
            if method == "POST":
                try:
                    body = write_resp.json()
                except Exception:
                    return None
                if not isinstance(body, dict):
                    return None
                resource_id = body.get("id") or body.get("_id") or body.get("uuid")
                if resource_id is None:
                    # No identifier to re-fetch by — check the create response itself.
                    return body
                fetch_url = f"{url.rstrip('/')}/{resource_id}"
            else:
                fetch_url = url

            get_resp = await client.get(fetch_url)
            if get_resp.status_code not in range(200, 300):
                return None
            return get_resp.json()
        except Exception:
            return None

    def _confirm_fields_applied(self, fetched: Optional[dict]) -> List[str]:
        """Check that the exact injected value (not just the field name) is present."""
        if not isinstance(fetched, dict):
            return []
        confirmed = []
        for field, injected_value in SENSITIVE_FIELDS.items():
            if field in fetched and fetched[field] == injected_value:
                confirmed.append(field)
        return confirmed
