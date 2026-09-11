import httpx
import re
from typing import List, Dict
from app.scanner.rules.base import BaseRule

# Payloads shaped to provoke a deserialization error if the endpoint blindly
# deserializes a query parameter (rather than just probing with no payload).
DESERIALIZATION_PAYLOADS = [
    "!!python/object/apply:os.system ['id']",   # YAML unsafe-load trigger
    "rO0ABXNyABFqYXZhLnV0aWwuSGFzaE1hcA==",     # Java serialized-object magic bytes (base64)
    "gASVFAAAAAAAAACMCG9zLnN5c3RlbZSMBmdldGN3ZJST",  # pickle opcode-shaped base64
]

STACK_TRACE_PATTERNS = [
    r"java\.io\.ObjectInputStream",
    r"ObjectInputStream\.readObject",
    r"org\.apache\.commons\.collections",
    r"BinaryFormatter\.Deserialize",
    r"System\.Runtime\.Serialization",
    r"pickle\.loads",
    r"yaml\.load\(",
    r"gson\.fromJson",
]

# A stack-trace-shaped body: multi-line, with a file/line reference.
_STACK_SHAPE = re.compile(r"(\.py\"|\.java:\d|\.cs:\d|line \d+|at [\w.$]+\()", re.IGNORECASE)


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

    async def run(self, target_url: str, endpoints: List[Dict], config: Dict, baseline_cache=None) -> List[Dict]:
        findings = []
        combined = re.compile("|".join(STACK_TRACE_PATTERNS), re.IGNORECASE)

        headers = {}
        if config.get("auth_header"):
            headers["Authorization"] = config["auth_header"]

        async with httpx.AsyncClient(verify=False, headers=headers, timeout=8.0) as client:
            for endpoint in endpoints:
                if endpoint["method"] != "GET":
                    continue
                path = endpoint["path"]
                url = f"{target_url}{path}"

                baseline = await baseline_cache.get(client, "GET", path) if baseline_cache else None
                if baseline and combined.search(baseline.body or ""):
                    # The pattern already appears on an unmodified request — it's
                    # not payload-triggered, so it's not a real signal here.
                    continue

                for payload in DESERIALIZATION_PAYLOADS:
                    try:
                        resp = await client.get(url, params={"data": payload})
                        text = resp.text

                        pattern_hit = combined.search(text)
                        if not pattern_hit:
                            continue

                        signals = ["payload_triggered_pattern"]
                        if resp.status_code >= 500:
                            signals.append("5xx_response")
                        if _STACK_SHAPE.search(text):
                            signals.append("stack_trace_shaped_body")

                        # Require at least the 5xx or stack-trace-shape signal in
                        # addition to the keyword hit — a bare keyword match in a
                        # 200 response (e.g. mentioned in docs) isn't enough.
                        if len(signals) < 2:
                            continue

                        findings.append(
                            self.build_finding(
                                description="Potential unsafe deserialization indicators found in response content.",
                                details={
                                    "status": resp.status_code,
                                    "payload": payload,
                                    "snippet": text[:500],
                                    "owasp": "API8: Security Misconfiguration",
                                },
                                endpoint=path,
                                method="GET",
                                severity="medium",
                                signals=signals,
                            )
                        )
                        break
                    except Exception:
                        continue

        return findings
