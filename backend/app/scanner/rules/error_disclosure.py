import re
import httpx
from typing import List, Dict
from app.scanner.rules.base import BaseRule

# Malformed inputs shaped to provoke an unhandled exception rather than a
# graceful 4xx validation error.
MALFORMED_JSON_BODIES = [
    '{"malformed": ',       # truncated JSON
    '{"a": [1,2,3,}',       # syntax error
]
TYPE_CONFUSION_VALUES = ["' OR 1=1--", "[]", "{}", "A" * 500]

# Generic framework/debug-page fingerprints — deliberately not the same set
# as DESERIALIZATION's patterns, which target specific deserialization
# libraries. These target "debug mode is on" broadly.
DEBUG_MARKERS = [
    r"Traceback \(most recent call last\)",
    r"Whitelabel Error Page",
    r"django\.core\.exceptions",
    r"django\.db\.utils",
    r"at Illuminate\\",
    r"Microsoft \.NET Framework",
    r"System\.Web\.HttpException",
    r"PHP Fatal error",
    r"Warning: (mysqli?|pg)_",
    r"org\.springframework\.\w+Exception",
    r"node_modules[\\/].*\.js:\d+",
    r"DEBUG\s*=\s*True",
    r"werkzeug\.exceptions",
]

# A stack-trace shape: file/line references, regardless of language.
_STACK_SHAPE = re.compile(
    r"(\.py\"|\.java:\d|\.cs:\d|\.rb:\d|\.php on line|line \d+, in |at [\w.$]+\()",
    re.IGNORECASE,
)


class ErrorDisclosureRule(BaseRule):
    id = "ERROR-DISCLOSURE"
    name = "Verbose Error / Debug Mode Disclosure"
    description = (
        "Sends malformed input designed to trigger an unhandled exception, then checks "
        "for stack traces or debug-mode output in the response."
    )
    severity = "medium"

    impact = (
        "Stack traces and debug pages can reveal internal file paths, framework/library "
        "versions, source snippets, and sometimes configuration or query details — all "
        "useful reconnaissance for a further attack."
    )
    remediation = "Disable debug/development mode in production and return generic error responses; log details server-side instead."
    cvss_vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"
    confidentiality = "Low"

    async def run(self, target_url: str, endpoints: List[Dict], config: Dict, baseline_cache=None) -> List[Dict]:
        findings = []
        combined = re.compile("|".join(DEBUG_MARKERS), re.IGNORECASE)

        headers = {}
        if config.get("auth_header"):
            headers["Authorization"] = config["auth_header"]

        async with httpx.AsyncClient(verify=False, headers=headers, timeout=8.0) as client:
            for endpoint in endpoints:
                method = endpoint.get("method", "GET").upper()
                path = endpoint.get("path", "/")
                if "{" in path:
                    # Path-param templates need real IDs from the spec — skip for now.
                    continue
                url = f"{target_url.rstrip('/')}{path}"

                baseline = await baseline_cache.get(client, method, path) if baseline_cache else None
                if baseline and combined.search(baseline.body or ""):
                    # Marker already present on an unmodified request — not payload-triggered.
                    continue

                if method in ("POST", "PUT", "PATCH"):
                    probes = [("body", b) for b in MALFORMED_JSON_BODIES]
                else:
                    probes = [("query", v) for v in TYPE_CONFUSION_VALUES]

                for kind, payload in probes:
                    try:
                        if kind == "body":
                            resp = await client.request(
                                method, url, content=payload,
                                headers={"Content-Type": "application/json"},
                            )
                        else:
                            resp = await client.request(method, url, params={"id": payload})
                    except Exception:
                        continue

                    text = resp.text
                    hit = combined.search(text)
                    if not hit:
                        continue

                    signals = ["debug_marker_new_vs_baseline"]
                    if resp.status_code >= 500:
                        signals.append("5xx_response")
                    if _STACK_SHAPE.search(text):
                        signals.append("stack_trace_shaped_body")

                    # Same bar as DESERIALIZATION: a bare keyword hit on a 200
                    # isn't enough on its own — require a corroborating signal.
                    if len(signals) < 2:
                        continue

                    findings.append(self.build_finding(
                        description="Malformed input triggered a verbose error response revealing internal implementation details.",
                        details={
                            "status": resp.status_code,
                            "matched_marker": hit.group(0),
                            "snippet": text[:500],
                            "owasp": "API8: Security Misconfiguration",
                        },
                        endpoint=path,
                        method=method,
                        proof_of_concept=f"{method} {url}\nPayload ({kind}): {payload}\nResponse: HTTP {resp.status_code}",
                        signals=signals,
                    ))
                    break

        return findings
