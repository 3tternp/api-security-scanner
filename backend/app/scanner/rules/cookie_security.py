import httpx
from typing import List, Dict, Tuple

from app.scanner.rules.base import BaseRule


class CookieSecurityRule(BaseRule):
    id = "COOKIE-SEC"
    name = "Cookie Security Flags Check"
    description = "Checks Set-Cookie attributes for HttpOnly, Secure, and SameSite."
    severity = "low"

    impact = "Missing cookie flags can enable session theft (XSS), credential exposure over plaintext, or CSRF."
    remediation = "Set HttpOnly; Secure (for HTTPS); and SameSite=Lax/Strict (or None+Secure when required)."
    cvss_vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N"
    confidentiality = "Low"
    integrity = "Low"
    availability = "None"

    async def run(self, target_url: str, endpoints: List[Dict], config: Dict) -> List[Dict]:
        base_url = target_url.rstrip("/")
        is_https = base_url.lower().startswith("https://")

        candidates = []
        for ep in endpoints:
            if ep.get("method") == "GET":
                candidates.append(ep)
        if not candidates:
            candidates = [{"path": "/", "method": "GET", "details": {}}]

        candidates = candidates[:5]

        headers = {}
        if config.get("auth_header"):
            headers["Authorization"] = config["auth_header"]

        cookie_issues: List[Dict] = []

        async with httpx.AsyncClient(verify=False, headers=headers, timeout=8.0, follow_redirects=False) as client:
            for ep in candidates:
                path = ep.get("path", "/")
                url = f"{base_url}{path}"
                try:
                    resp = await client.get(url)
                except Exception:
                    continue

                set_cookies = resp.headers.get_list("set-cookie")
                for raw in set_cookies:
                    name, attrs = self._parse_set_cookie(raw)
                    issues = []

                    if "httponly" not in attrs:
                        issues.append("Missing HttpOnly")
                    if is_https and "secure" not in attrs:
                        issues.append("Missing Secure")

                    same_site = attrs.get("samesite")
                    if not same_site:
                        issues.append("Missing SameSite")
                    elif same_site.lower() == "none" and "secure" not in attrs:
                        issues.append("SameSite=None without Secure")

                    if issues:
                        cookie_issues.append(
                            {
                                "url": url,
                                "cookie": name,
                                "issues": issues,
                                "raw": raw,
                            }
                        )

        if not cookie_issues:
            return []

        severity = "medium" if any("Missing HttpOnly" in c["issues"] or "SameSite=None without Secure" in c["issues"] for c in cookie_issues) else "low"

        return [
            self.build_finding(
                description="Insecure cookie attributes detected in Set-Cookie headers.",
                details={
                    "is_https_target": is_https,
                    "affected": cookie_issues,
                    "note": "Some APIs do not use cookies; if your API is token-only, Set-Cookie findings may be from ancillary endpoints.",
                },
                endpoint="/",
                method="GET",
                severity=severity,
                proof_of_concept="\n".join([c["raw"] for c in cookie_issues][:5]),
            )
        ]

    def _parse_set_cookie(self, raw: str) -> Tuple[str, Dict[str, str]]:
        parts = [p.strip() for p in raw.split(";") if p.strip()]
        if not parts:
            return ("<unknown>", {})

        name_part = parts[0]
        name = name_part.split("=", 1)[0].strip() or "<unknown>"

        attrs: Dict[str, str] = {}
        for p in parts[1:]:
            if "=" in p:
                k, v = p.split("=", 1)
                attrs[k.strip().lower()] = v.strip()
            else:
                attrs[p.strip().lower()] = "true"

        return (name, attrs)
