from typing import List, Dict
import httpx
from app.scanner.rules.base import BaseRule


ADMIN_PATH_KEYWORDS = [
    "/admin", "/manage", "/internal", "/console",
    "/config", "/settings", "/superuser", "/staff",
]

# A low-privilege token — obviously invalid to real servers, but
# some implementations only check for *any* token rather than validating it
LOW_PRIV_TOKEN = (
    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
    ".eyJzdWIiOiJ1c2VyIiwicm9sZSI6InVzZXIiLCJleHAiOjk5OTk5OTk5OTl9"
    ".low_privilege_placeholder_signature"
)

GARBAGE_TOKEN = "Bearer not-a-real-token-abc123"


class BrokenFunctionAuthRule(BaseRule):
    id = "BFLA-001"
    name = "Broken Function Level Authorization (BFLA)"
    severity = "high"
    impact = (
        "Unauthorised users can access administrative or privileged functions, "
        "allowing account takeover, data exfiltration, and destructive actions."
    )
    remediation = (
        "Enforce function-level access controls on every endpoint. "
        "Do not rely solely on UI hiding or client-side checks. "
        "Apply role-based access control (RBAC) server-side and default to deny."
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

        admin_endpoints = [
            ep for ep in endpoints
            if any(kw in ep.get("path", "").lower() for kw in ADMIN_PATH_KEYWORDS)
        ]

        if not admin_endpoints:
            return findings

        # Control endpoint: a known-non-admin path, used to check whether the
        # server behaves differently for admin paths at all, or whether it's
        # simply open everywhere (in which case flagging the admin path alone
        # isn't a distinctive BFLA signal).
        control_ep = next(
            (ep for ep in endpoints if ep.get("method", "GET").upper() == "GET"
             and not any(kw in ep.get("path", "").lower() for kw in ADMIN_PATH_KEYWORDS)),
            None,
        )
        control_path = control_ep.get("path", "/") if control_ep else "/"

        async with httpx.AsyncClient(verify=False, timeout=8.0) as client:
            control_status = None
            try:
                control_resp = await client.get(f"{target_url.rstrip('/')}{control_path}")
                control_status = control_resp.status_code
            except Exception:
                pass

            for ep in admin_endpoints:
                path = ep.get("path", "/")
                method = ep.get("method", "GET").upper()
                url = f"{target_url.rstrip('/')}{path}"

                # --- Test 1: No Authorization header at all ---
                try:
                    resp = await client.request(
                        method,
                        url,
                        json={} if method in ("POST", "PUT", "PATCH") else None,
                    )
                    if resp.status_code == 200:
                        signals = ["admin_path_no_auth_200"]
                        if control_status != 200:
                            signals.append("differs_from_control_path")
                        findings.append(self.build_finding(
                            description="Admin/management endpoint accessible without authentication.",
                            details=(
                                f"The endpoint returned HTTP 200 with no Authorization header. "
                                f"Administrative functionality is publicly accessible. "
                                f"Control path '{control_path}' returned {control_status}. "
                                f"URL: {url}, Method: {method}"
                            ),
                            endpoint=path,
                            method=method,
                            proof_of_concept=(
                                f"{method} {url}\n"
                                f"(No Authorization header)\n"
                                f"Response: HTTP 200"
                            ),
                            signals=signals,
                        ))
                except Exception:
                    pass

                # --- Test 2: Low-privilege token vs. a syntactically garbage token ---
                try:
                    resp = await client.request(
                        method,
                        url,
                        headers={"Authorization": f"Bearer {LOW_PRIV_TOKEN}"},
                        json={} if method in ("POST", "PUT", "PATCH") else None,
                    )
                    if resp.status_code == 200:
                        signals = ["low_priv_token_accepted"]
                        # If a garbage token gets rejected while a well-formed,
                        # low-privilege token succeeds, the server IS validating
                        # tokens but not enforcing the role/privilege claim —
                        # a much stronger BFLA signal than a bare 200.
                        try:
                            garbage_resp = await client.request(
                                method, url, headers={"Authorization": GARBAGE_TOKEN},
                                json={} if method in ("POST", "PUT", "PATCH") else None,
                            )
                            if garbage_resp.status_code in (401, 403):
                                signals.append("role_not_enforced_but_token_validated")
                        except Exception:
                            pass

                        findings.append(self.build_finding(
                            description="Admin/management endpoint accessible with low-privilege token.",
                            details=(
                                f"The endpoint returned HTTP 200 when accessed with a token "
                                f"bearing only 'user' role. Privilege escalation may be possible. "
                                f"URL: {url}, Method: {method}"
                            ),
                            endpoint=path,
                            method=method,
                            proof_of_concept=(
                                f"{method} {url}\n"
                                f"Authorization: Bearer <low-privilege-token>\n"
                                f"Response: HTTP 200"
                            ),
                            signals=signals,
                        ))
                except Exception:
                    pass

        return findings
