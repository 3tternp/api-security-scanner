import httpx
from typing import List, Dict
from app.scanner.rules.base import BaseRule
from app.scanner.signals import is_html_context
import urllib.parse

class InjectionRule(BaseRule):
    id = "INJECTION-BASIC"
    name = "Basic Injection Check (SQLi/XSS)"
    description = "Checks for basic SQL injection and XSS vulnerabilities in query parameters."
    severity = "high"

    impact = "Attackers may read/modify sensitive data (SQLi) or execute malicious scripts in user browsers (XSS)."
    remediation = "Use parameterized queries (Prepared Statements) for SQL. Use output encoding/escaping for XSS prevention. Validate all input."
    cvss_vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    confidentiality = "High"
    integrity = "High"
    availability = "High"

    async def run(self, target_url: str, endpoints: List[Dict], config: Dict, baseline_cache=None) -> List[Dict]:
        findings = []
        payloads = {
            "SQLi": ["'", "\"", " OR 1=1", "' OR '1'='1"],
            "XSS": ["<script>alert(1)</script>", "\"><script>alert(1)</script>"]
        }

        async with httpx.AsyncClient(verify=False) as client:
            headers = {}
            if config.get('auth_header'):
                headers['Authorization'] = config['auth_header']

            for endpoint in endpoints:
                if endpoint['method'] != 'GET':
                    continue

                path = endpoint['path']
                base_url = f"{target_url}{path}"

                baseline = await baseline_cache.get(client, "GET", path) if baseline_cache else None
                baseline_text = (baseline.body if baseline else "").lower()
                baseline_content_type = baseline.headers.get("content-type", "") if baseline else ""

                for p_type, p_list in payloads.items():
                    for payload in p_list:
                        if '{' in base_url:
                            # Path-param replacement needs real IDs from the spec — skip for now.
                            continue
                        test_url = f"{base_url}?q={urllib.parse.quote(payload)}"

                        try:
                            response = await client.get(test_url, headers=headers)
                        except Exception:
                            continue

                        if p_type == "SQLi":
                            errors = ["syntax error", "mysql", "postgres", "sqlite", "oracle"]
                            probe_text = response.text.lower()
                            # Only count an error keyword if it's new — i.e. not
                            # already present on the unmodified baseline request
                            # (which would mean it's unrelated to our payload).
                            new_errors = [e for e in errors if e in probe_text and e not in baseline_text]
                            if new_errors:
                                findings.append(self.build_finding(
                                    description=f"Possible SQL Injection detected with payload: {payload}",
                                    details={
                                        "url": test_url,
                                        "response_snippet": response.text[:200],
                                        "matched_errors": new_errors,
                                        "owasp": "API8: Security Misconfiguration"
                                    },
                                    endpoint=path,
                                    method="GET",
                                    severity="high",
                                    signals=["sql_error_keyword_new_vs_baseline"],
                                ))

                        elif p_type == "XSS":
                            content_type = response.headers.get("content-type", "")
                            if payload in response.text and payload not in (baseline.body if baseline else ""):
                                signals = ["payload_reflected_verbatim"]
                                if is_html_context(content_type):
                                    signals.append("html_content_type")
                                # Require HTML context for a real reflected-XSS
                                # risk — a verbatim match inside a JSON string
                                # value isn't executable in a browser.
                                if "html_content_type" not in signals:
                                    continue
                                findings.append(self.build_finding(
                                    description=f"Reflected XSS detected with payload: {payload}",
                                    details={
                                        "url": test_url,
                                        "content_type": content_type,
                                        "owasp": "API8: Security Misconfiguration"
                                    },
                                    endpoint=path,
                                    method="GET",
                                    severity="high",
                                    signals=signals,
                                ))

        return findings
