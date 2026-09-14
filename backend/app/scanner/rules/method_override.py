import httpx
from typing import List, Dict
from app.scanner.rules.base import BaseRule
from app.scanner.allowlists import is_public_path

# Headers some frameworks/proxies honor to let a client claim a different HTTP
# method than the one actually sent on the wire — meant for clients behind
# restrictive networks, but if an access-control layer only inspects the
# literal request line, this can smuggle a restricted method past it.
OVERRIDE_HEADERS = [
    "X-HTTP-Method-Override",
    "X-HTTP-Method",
    "X-Method-Override",
]

RESTRICTED_METHODS = ("PUT", "PATCH", "DELETE")


class MethodOverrideRule(BaseRule):
    id = "METHOD-OVERRIDE-001"
    name = "HTTP Method Override Authorization Bypass"
    description = (
        "Checks whether a method-override header lets a caller reach an operation "
        "that is denied when the real HTTP method is used directly."
    )
    severity = "high"

    impact = (
        "An access-control layer that only inspects the literal HTTP method (rather than "
        "the method an override header causes the application to actually dispatch to) "
        "can be bypassed, letting an unauthenticated or under-privileged caller perform "
        "a restricted write/delete operation."
    )
    remediation = (
        "Do not honor X-HTTP-Method-Override (or equivalents) on endpoints protected by "
        "method-based access control, or apply identical authorization checks regardless "
        "of which method the request is ultimately routed as."
    )
    cvss_vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"
    attack_vector = "Network"
    attack_complexity = "Low"
    privileges_required = "None"
    user_interaction = "None"
    confidentiality = "High"
    integrity = "High"

    async def run(self, target_url: str, endpoints: List[Dict], config: Dict, baseline_cache=None) -> List[Dict]:
        findings = []

        candidates = [
            ep for ep in endpoints
            if ep.get("method", "GET").upper() in RESTRICTED_METHODS
            and not is_public_path(ep.get("path", ""))
        ]

        async with httpx.AsyncClient(verify=False, timeout=8.0) as client:
            for ep in candidates:
                path = ep.get("path", "/")
                method = ep.get("method", "POST").upper()
                url = f"{target_url.rstrip('/')}{path}"

                # Baseline: is the real method denied with no credentials at all?
                # If it isn't, there's nothing here to bypass.
                try:
                    baseline_resp = await client.request(method, url, json={})
                except Exception:
                    continue
                if baseline_resp.status_code not in (401, 403, 405):
                    continue

                # Control: a bare POST with no override header, no credentials.
                # If this alone already succeeds, the path just accepts POST
                # normally — an override-header "bypass" wouldn't mean anything.
                try:
                    control_resp = await client.post(url, json={})
                except Exception:
                    continue
                if control_resp.status_code in (200, 201, 202, 204):
                    continue

                for header in OVERRIDE_HEADERS:
                    try:
                        resp = await client.post(url, headers={header: method}, json={})
                    except Exception:
                        continue

                    if resp.status_code in (200, 201, 202, 204):
                        signals = [
                            "real_method_denied",
                            "control_post_without_override_denied",
                            f"bypassed_via_{header.lower()}",
                        ]
                        findings.append(self.build_finding(
                            description=(
                                f"{method} {path} is denied without credentials, but the same "
                                f"operation succeeds via POST carrying a '{header}: {method}' header."
                            ),
                            details={
                                "url": url,
                                "real_method_status": baseline_resp.status_code,
                                "control_post_status": control_resp.status_code,
                                "override_header": header,
                                "override_status": resp.status_code,
                                "owasp": "API2: Broken Authentication",
                            },
                            endpoint=path,
                            method=method,
                            proof_of_concept=(
                                f"{method} {url} -> HTTP {baseline_resp.status_code} (denied)\n"
                                f"POST {url} -> HTTP {control_resp.status_code} (control, denied)\n"
                                f"POST {url}\n{header}: {method}\n-> HTTP {resp.status_code}"
                            ),
                            signals=signals,
                        ))
                        break  # one confirmed bypass per endpoint is enough

        return findings
