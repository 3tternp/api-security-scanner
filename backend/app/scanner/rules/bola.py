import httpx
import re
from typing import List, Dict
from app.scanner.rules.base import BaseRule
from app.scanner.signals import diff_json_bodies

class BolaRule(BaseRule):
    id = "BOLA-IDOR"
    name = "Broken Object Level Authorization (IDOR)"
    description = "Checks for Insecure Direct Object References by modifying resource IDs."
    severity = "high"

    impact = "Unauthorized access to other users' data."
    remediation = "Implement proper access control checks. Ensure the authenticated user is authorized to access the requested resource ID."
    cvss_vector = "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N"
    confidentiality = "High"
    integrity = "High"
    availability = "None"

    async def run(self, target_url: str, endpoints: List[Dict], config: Dict, baseline_cache=None) -> List[Dict]:
        findings = []

        # Pattern to find IDs in paths, e.g., /users/123 or /orders/5
        id_pattern = re.compile(r'/(\d+)(/|$)')

        async with httpx.AsyncClient(verify=False) as client:
            headers = {}
            if config.get('auth_header'):
                headers['Authorization'] = config['auth_header']

            for endpoint in endpoints:
                if endpoint['method'] != 'GET':
                    continue

                path = endpoint['path']
                match = id_pattern.search(path)

                if not match:
                    continue

                original_id = match.group(1)
                try:
                    test_id = str(int(original_id) + 1)
                    if test_id == original_id:
                        test_id = str(int(original_id) - 1)
                except ValueError:
                    continue

                test_path = path.replace(f"/{original_id}", f"/{test_id}", 1)

                original_url = f"{target_url}{path}"
                test_url = f"{target_url}{test_path}"

                try:
                    resp_orig = await client.get(original_url, headers=headers)
                    if resp_orig.status_code != 200:
                        continue  # If original not accessible, can't test BOLA

                    # Same-ID repeat request: establishes what "normal noise"
                    # looks like (timestamps, counters) so it isn't mistaken
                    # for a real cross-owner difference.
                    resp_repeat = await client.get(original_url, headers=headers)

                    resp_test = await client.get(test_url, headers=headers)
                    if resp_test.status_code != 200:
                        continue

                    repeat_diff = diff_json_bodies(resp_orig.text, resp_repeat.text)
                    test_diff = diff_json_bodies(resp_orig.text, resp_test.text)

                    signals = []
                    if test_diff["parsed"]:
                        # Only trust the owner-field diff if the same-ID repeat
                        # request did NOT show the same fields drifting (that
                        # would mean the field is just noisy, not owner-specific).
                        if test_diff["owner_fields_differ"] and not repeat_diff["owner_fields_differ"]:
                            signals.append("owner_field_differs")
                            signals.append("structured_diff_confirmed")
                    else:
                        # Fallback when responses aren't JSON: compare content-length
                        # delta against the same-ID repeat baseline instead of raw
                        # text equality, so pagination/timestamp noise doesn't count.
                        orig_len = len(resp_orig.text)
                        repeat_delta = abs(len(resp_repeat.text) - orig_len)
                        test_delta = abs(len(resp_test.text) - orig_len)
                        if orig_len > 0 and test_delta > max(repeat_delta * 3, orig_len * 0.1):
                            signals.append("content_length_delta_exceeds_baseline_noise")

                    if not signals:
                        continue

                    findings.append(self.build_finding(
                        description=f"Potential BOLA/IDOR: Accessible resource {test_path} (modified from {path}).",
                        details={
                            "original_url": original_url,
                            "test_url": test_url,
                            "original_status": resp_orig.status_code,
                            "test_status": resp_test.status_code,
                            "differing_fields": test_diff.get("differing_fields", []),
                            "owasp": "API1: Broken Object Level Authorization"
                        },
                        endpoint=path,
                        method="GET",
                        severity="high",
                        signals=signals,
                    ))
                except Exception:
                    pass

        return findings
