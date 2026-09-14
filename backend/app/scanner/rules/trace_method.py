import secrets
import httpx
from typing import List, Dict
from app.scanner.rules.base import BaseRule


class TraceMethodRule(BaseRule):
    id = "TRACE-METHOD-001"
    name = "HTTP TRACE Method Enabled (XST)"
    description = (
        "Checks whether the HTTP TRACE method is enabled, which can be abused for "
        "Cross-Site Tracing (XST) to read HttpOnly cookies and headers via a separate "
        "script-injection bug."
    )
    severity = "medium"

    impact = (
        "If TRACE is enabled, an attacker who can run script in the victim's browser "
        "(e.g. via a reflected XSS elsewhere on the site) can issue a TRACE request and "
        "read the echoed response to recover cookies and headers marked HttpOnly, "
        "defeating that protection."
    )
    remediation = "Disable the TRACE (and TRACK) HTTP method at the web server / reverse proxy / load balancer level."
    cvss_vector = "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N"
    attack_complexity = "High"
    confidentiality = "Low"

    # TRACE support is a server/proxy-level setting, not per-endpoint — testing
    # a handful of distinct paths is enough; no need to hit every endpoint.
    MAX_PATHS_TESTED = 5

    async def run(self, target_url: str, endpoints: List[Dict], config: Dict, baseline_cache=None) -> List[Dict]:
        findings = []
        canary = f"xst-canary-{secrets.token_hex(6)}"

        paths = []
        seen = set()
        for ep in endpoints:
            path = ep.get("path", "/")
            if path not in seen:
                seen.add(path)
                paths.append(path)
            if len(paths) >= self.MAX_PATHS_TESTED:
                break
        if not paths:
            paths = ["/"]

        async with httpx.AsyncClient(verify=False, timeout=8.0) as client:
            for path in paths:
                url = f"{target_url.rstrip('/')}{path}"
                try:
                    resp = await client.request("TRACE", url, headers={"X-Xst-Canary": canary})
                except Exception:
                    continue

                # The distinctive signal is not "TRACE didn't 4xx" (some proxies
                # return 200 with an unrelated body for any method) — it's that
                # our own injected canary header comes back inside the response
                # body, proving the server echoed the raw request.
                if resp.status_code < 400 and canary in resp.text:
                    signals = ["trace_request_echoed_canary_header"]
                    content_type = resp.headers.get("content-type", "")
                    if "message/http" in content_type.lower():
                        signals.append("message_http_content_type")

                    findings.append(self.build_finding(
                        description="HTTP TRACE method is enabled and echoes request headers back in the response body.",
                        details={
                            "status": resp.status_code,
                            "url": url,
                            "content_type": content_type,
                            "owasp": "API8: Security Misconfiguration",
                        },
                        endpoint=path,
                        method="TRACE",
                        proof_of_concept=(
                            f"TRACE {url}\nX-Xst-Canary: {canary}\n"
                            f"Response (HTTP {resp.status_code}) echoed the canary value back in its body."
                        ),
                        signals=signals,
                    ))
                    # Server/proxy-level setting — one confirmed hit is enough.
                    break

        return findings
