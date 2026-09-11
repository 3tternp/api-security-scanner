import httpx
from typing import List, Dict
from app.scanner.rules.base import BaseRule

class FuzzingRule(BaseRule):
    id = "FUZZING"
    name = "Fuzzing-based Input Robustness"
    description = "Sends fuzzed query parameters and bodies to detect crashes and 5xx errors."
    severity = "medium"
    impact = "Unvalidated input may cause crashes or expose internal error details."
    remediation = "Validate and sanitize all inputs. Handle unexpected input types gracefully."
    cvss_vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L"
    confidentiality = "Low"
    integrity = "Low"
    availability = "Low"

    async def _confirmed_5xx(self, client, request_fn, baseline_status) -> bool:
        """A 5xx only counts if it reproduces on retry and isn't already the
        endpoint's baseline behavior (transient errors/rate-limit 5xx aren't
        payload-specific bugs)."""
        if baseline_status is not None and baseline_status >= 500:
            return False
        try:
            resp1 = await request_fn()
            if resp1.status_code < 500:
                return False
            resp2 = await request_fn()
            return resp2.status_code >= 500
        except Exception:
            return False

    async def run(self, target_url: str, endpoints: List[Dict], config: Dict, baseline_cache=None) -> List[Dict]:
        findings = []
        fuzz_values = [
            "A" * 512,
            "' OR '1'='1",
            "<script>alert(1)</script>",
            "../../etc/passwd",
            "\x00\x00\x00\x00",
            "🔥💥 fuzz 💥🔥",
        ]

        headers = {}
        if config.get("auth_header"):
            headers["Authorization"] = config["auth_header"]

        async with httpx.AsyncClient(verify=False, headers=headers) as client:
            for endpoint in endpoints:
                path = endpoint["path"]
                method = endpoint["method"].upper()
                url = f"{target_url}{path}"

                baseline = await baseline_cache.get(client, method, path) if baseline_cache else None
                baseline_status = baseline.status_code if baseline else None

                if method == "GET":
                    for value in fuzz_values:
                        confirmed = await self._confirmed_5xx(
                            client, lambda v=value: client.get(url, params={"q": v}), baseline_status
                        )
                        if confirmed:
                            findings.append(
                                self.build_finding(
                                    description="Endpoint reproducibly returns 5xx error for fuzzed query parameter.",
                                    details={
                                        "payload": value,
                                        "baseline_status": baseline_status,
                                        "owasp": "API8: Security Misconfiguration",
                                    },
                                    endpoint=path,
                                    method="GET",
                                    severity="medium",
                                    signals=["reproduced_5xx", "absent_on_baseline"],
                                )
                            )
                            break

                if method == "POST":
                    for value in fuzz_values:
                        body = {"fuzz": value}
                        confirmed = await self._confirmed_5xx(
                            client, lambda b=body: client.post(url, json=b), baseline_status
                        )
                        if confirmed:
                            findings.append(
                                self.build_finding(
                                    description="Endpoint reproducibly returns 5xx error for fuzzed JSON body.",
                                    details={
                                        "payload": body,
                                        "baseline_status": baseline_status,
                                        "owasp": "API8: Security Misconfiguration",
                                    },
                                    endpoint=path,
                                    method="POST",
                                    severity="medium",
                                    signals=["reproduced_5xx", "absent_on_baseline"],
                                )
                            )
                            break

        return findings
