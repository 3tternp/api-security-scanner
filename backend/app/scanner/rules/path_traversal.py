import re
from typing import List, Dict, Optional
import httpx
from app.scanner.rules.base import BaseRule, bounded_gather


TRAVERSAL_PAYLOADS = [
    "../../../etc/passwd",
    "..%2F..%2F..%2Fetc%2Fpasswd",
    "....//....//....//etc/passwd",
    "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
    "..\\..\\..\\etc\\passwd",
    "/etc/passwd",
]

# A precise match on the classic /etc/passwd root entry format
# ("root:x:0:0:root:/root:/bin/bash") — distinctive enough on its own that a
# match is essentially conclusive proof of a file read, not a coincidental
# substring hit.
PASSWD_ROOT_LINE_RE = re.compile(r"root:[^\n:]*:0:0:")

# Weaker substring markers — individually these can false-positive on
# unrelated text (e.g. "bin:" matches inside "Robin:", "root:" can appear in
# config dumps), so they're only trusted when at least two distinct markers
# co-occur, mirroring how a real /etc/passwd listing has multiple colon-
# delimited lines rather than one isolated word.
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

    def _evaluate(self, body: str):
        """Return (triggered, signals, confidence, matched_marker) for a probe response body."""
        if PASSWD_ROOT_LINE_RE.search(body):
            # The exact "root:x:0:0:...:/bin/*sh" line shape is essentially
            # conclusive on its own — treat it as high confidence regardless
            # of the (single) signal count.
            return True, ["passwd_root_line_format_match"], "high", "root:x:0:0:...:/bin/*sh"

        matched = [m for m in UNIX_PASSWD_MARKERS if m in body]
        if len(matched) >= 2:
            # Individually weak substrings (e.g. "bin:" alone can false-match
            # "Robin:") — only trust them once several distinct markers
            # co-occur, and score confidence off how many independently did.
            signals = [f"passwd_marker:{m}" for m in matched]
            return True, signals, None, ", ".join(matched)
        return False, [], None, None

    async def _probe_query(self, client, target_url, ep, payload, param) -> Optional[Dict]:
        path = ep.get("path", "/")
        url = f"{target_url.rstrip('/')}{path}"
        try:
            resp = await client.get(url, params={param: payload})
            triggered, signals, confidence, marker = self._evaluate(resp.text)
            if not triggered:
                return None
            return self.build_finding(
                description="Path traversal vulnerability confirmed — /etc/passwd read.",
                details=(
                    f"The payload '{payload}' supplied via the '{param}' "
                    f"query parameter caused the server to return contents "
                    f"matching '{marker}', indicating "
                    f"/etc/passwd was read. "
                    f"URL: {url}, HTTP status: {resp.status_code}"
                ),
                endpoint=path,
                method="GET",
                proof_of_concept=(
                    f"GET {url}?{param}={payload}\n"
                    f"Response contained: '{marker}'"
                ),
                signals=signals,
                confidence=confidence,
            )
        except Exception:
            pass
        return None

    async def _probe_path_suffix(self, client, target_url, ep, payload) -> Optional[Dict]:
        path = ep.get("path", "/")
        url = f"{target_url.rstrip('/')}{path}"
        traversal_url = f"{url}/{payload}"
        try:
            resp = await client.get(traversal_url)
            triggered, signals, confidence, marker = self._evaluate(resp.text)
            if not triggered:
                return None
            return self.build_finding(
                description="Path traversal vulnerability confirmed via URL path.",
                details=(
                    f"Appending the traversal payload '{payload}' to the "
                    f"endpoint path caused the server to return contents "
                    f"matching '{marker}', indicating /etc/passwd was read. "
                    f"URL: {traversal_url}, HTTP status: {resp.status_code}"
                ),
                endpoint=f"{path}/{payload}",
                method="GET",
                proof_of_concept=(
                    f"GET {traversal_url}\n"
                    f"Response contained: '{marker}'"
                ),
                signals=signals,
                confidence=confidence,
            )
        except Exception:
            pass
        return None

    async def _probe_body(self, client, target_url, ep, payload, param) -> Optional[Dict]:
        path = ep.get("path", "/")
        method = ep.get("method", "GET").upper()
        url = f"{target_url.rstrip('/')}{path}"
        try:
            resp = await client.request(method, url, json={param: payload})
            triggered, signals, confidence, marker = self._evaluate(resp.text)
            if not triggered:
                return None
            return self.build_finding(
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
                signals=signals,
                confidence=confidence,
            )
        except Exception:
            pass
        return None

    async def run(self, target_url: str, endpoints: List[Dict], config: Dict, baseline_cache=None) -> List[Dict]:
        findings = []

        # Prioritise endpoints that look like they serve files
        file_endpoints = [
            ep for ep in endpoints
            if any(kw in ep.get("path", "").lower() for kw in FILE_PATH_KEYWORDS)
        ]
        if not file_endpoints:
            file_endpoints = endpoints

        headers = {}
        if config.get('auth_header'):
            headers['Authorization'] = config['auth_header']

        async with httpx.AsyncClient(verify=False, timeout=8.0, headers=headers) as client:
            # Every (endpoint, payload, param) combination used to be awaited
            # one at a time — up to 6 payloads x 25 params/variants per
            # endpoint, fully serial. Run them concurrently (bounded) instead.
            tasks = []
            for ep in file_endpoints:
                method = ep.get("method", "GET").upper()
                for payload in TRAVERSAL_PAYLOADS:
                    for param in FILE_PARAM_NAMES:
                        tasks.append(self._probe_query(client, target_url, ep, payload, param))
                    tasks.append(self._probe_path_suffix(client, target_url, ep, payload))
                    if method in ("POST", "PUT", "PATCH"):
                        for param in FILE_PARAM_NAMES:
                            tasks.append(self._probe_body(client, target_url, ep, payload, param))

            results = await bounded_gather(tasks, limit=15)

            seen = set()  # (endpoint, method) -> keep first confirmed hit, same as old "break"
            for finding in results:
                if not finding or isinstance(finding, Exception):
                    continue
                key = (finding["endpoint"], finding["method"])
                if key in seen:
                    continue
                seen.add(key)
                findings.append(finding)

        return findings
