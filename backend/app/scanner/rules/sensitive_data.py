import httpx
import re
from typing import List, Dict
from app.scanner.rules.base import BaseRule

# Domains/local-parts that show up constantly in fixtures, examples, and
# schema documentation rather than real user data — flagging these as PII
# exposure is noise, not a finding.
_PLACEHOLDER_EMAIL_RE = re.compile(
    r'@(example\.(com|org|net)|test\.(com|org)|localhost|sample\.com|acme\.com|domain\.com|email\.com)$',
    re.IGNORECASE,
)
_PLACEHOLDER_LOCAL_PARTS = {"test", "user", "example", "foo", "bar", "admin", "john.doe", "jane.doe"}

# Endpoints where returning a bearer/session token in the body is the whole
# point of the endpoint, not a leak of a secret the caller didn't ask for.
AUTH_PATH_KEYWORDS = ["/login", "/auth", "/token", "/signin", "/oauth", "/session", "/refresh"]

AUTH_KEY_FIELD_RE = re.compile(r'(?i)(api_key|apikey|secret|token)["\']?\s*[:=]\s*["\']?([a-zA-Z0-9._-]{16,})["\']?')


class SensitiveDataRule(BaseRule):
    id = "SENSITIVE-DATA"
    name = "Sensitive Data Exposure"
    description = "Checks for sensitive information (PII, secrets) in API responses."
    severity = "high"

    impact = "Loss of confidentiality, identity theft, or compromise of backend systems (if keys leaked)."
    remediation = "Ensure sensitive data is not returned in API responses. Use PII masking. Store secrets securely."
    cvss_vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"
    confidentiality = "High"

    PATTERNS = {
        "Email": re.compile(r'[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+'),
        "SSN (US)": re.compile(r'\b\d{3}-\d{2}-\d{4}\b'),
    }

    def _is_placeholder_email(self, email: str) -> bool:
        if _PLACEHOLDER_EMAIL_RE.search(email):
            return True
        local_part = email.split("@", 1)[0].lower()
        return local_part in _PLACEHOLDER_LOCAL_PARTS

    def _is_own_account_email(self, email: str, config: Dict) -> bool:
        own = (config.get("account_email") or config.get("username") or "").strip().lower()
        return bool(own) and email.lower() == own

    async def run(self, target_url: str, endpoints: List[Dict], config: Dict, baseline_cache=None) -> List[Dict]:
        findings = []

        async with httpx.AsyncClient(verify=False, timeout=8.0) as client:
            headers = {}
            if config.get('auth_header'):
                headers['Authorization'] = config['auth_header']

            for endpoint in endpoints:
                if endpoint['method'] != 'GET':
                    continue

                path = endpoint['path']
                is_auth_endpoint = any(kw in path.lower() for kw in AUTH_PATH_KEYWORDS)
                url = f"{target_url}{path}"

                try:
                    response = await client.get(url, headers=headers)
                except Exception:
                    continue

                if response.status_code != 200:
                    # Only trust data that was actually served back, not an
                    # error page (which may echo request content, config
                    # paths, etc. unrelated to genuine data exposure).
                    continue

                text = response.text

                # --- Emails ---
                emails = self.PATTERNS["Email"].findall(text)
                real_emails = [
                    e for e in dict.fromkeys(emails)  # de-dupe, preserve order
                    if not self._is_placeholder_email(e) and not self._is_own_account_email(e, config)
                ]
                if real_emails:
                    signals = ["email_pattern_match"]
                    if len(real_emails) > 1:
                        # Multiple distinct real addresses strongly suggests a
                        # user listing/export rather than one incidental
                        # contact-us address in a footer.
                        signals.append("multiple_distinct_addresses")
                    findings.append(self.build_finding(
                        description="Potential Email exposure in response.",
                        details={
                            "count": len(real_emails),
                            "snippet": str(real_emails[:3]),
                            "owasp": "API3: Broken Object Property Level Authorization"
                        },
                        endpoint=path,
                        method="GET",
                        severity="medium",
                        signals=signals,
                    ))

                # --- SSNs ---
                ssns = self.PATTERNS["SSN (US)"].findall(text)
                if ssns:
                    findings.append(self.build_finding(
                        description="Potential SSN (US) exposure in response.",
                        details={
                            "count": len(ssns),
                            "snippet": str(ssns[:3]),
                            "owasp": "API3: Broken Object Property Level Authorization"
                        },
                        endpoint=path,
                        method="GET",
                        severity="high",
                        # A 3-2-4 digit pattern is fairly distinctive on its
                        # own (unlike a bare email), so one match is enough
                        # to warrant at least medium confidence.
                        signals=["ssn_pattern_match", "distinctive_format"],
                    ))

                # --- API keys / secrets / tokens ---
                if not is_auth_endpoint:
                    # A login/token/auth endpoint returning a bearer token is
                    # expected behavior, not a leak — only flag key-shaped
                    # values on endpoints that aren't supposed to hand out
                    # credentials in the first place.
                    key_matches = AUTH_KEY_FIELD_RE.findall(text)
                    if key_matches:
                        findings.append(self.build_finding(
                            description="Potential API Key exposure in response.",
                            details={
                                "count": len(key_matches),
                                "snippet": str([m[0] for m in key_matches[:3]]),
                                "owasp": "API3: Broken Object Property Level Authorization"
                            },
                            endpoint=path,
                            method="GET",
                            severity="high",
                            signals=["secret_field_pattern_match", "non_auth_endpoint"],
                        ))

        return findings
