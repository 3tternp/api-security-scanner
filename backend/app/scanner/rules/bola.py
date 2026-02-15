import httpx
import re
from typing import List, Dict
from app.scanner.rules.base import BaseRule

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

    async def run(self, target_url: str, endpoints: List[Dict], config: Dict) -> List[Dict]:
        findings = []
        
        # Pattern to find IDs in paths, e.g., /users/123 or /orders/5
        # Matches integer IDs at end of path or between slashes
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
                
                if match:
                    original_id = match.group(1)
                    # Try a simple increment/decrement
                    try:
                        test_id = str(int(original_id) + 1)
                        if test_id == original_id:
                            test_id = str(int(original_id) - 1)
                    except:
                        continue

                    # Construct test URL
                    # Replace ONLY the found ID
                    # Note: simple replacement might be risky if ID appears multiple times, but acceptable for PoC
                    test_path = path.replace(f"/{original_id}", f"/{test_id}", 1) 
                    
                    original_url = f"{target_url}{path}"
                    test_url = f"{target_url}{test_path}"
                    
                    try:
                        # 1. Request Original (should be accessible if valid)
                        resp_orig = await client.get(original_url, headers=headers)
                        if resp_orig.status_code != 200:
                            continue # If original not accessible, can't test BOLA

                        resp_test = await client.get(test_url, headers=headers)
                        if resp_test.status_code == 200:
                            body_orig = resp_orig.text
                            body_test = resp_test.text
                            if body_orig != body_test:
                                findings.append(self.build_finding(
                                    description=f"Potential BOLA/IDOR: Accessible resource {test_path} (modified from {path}).",
                                    details={
                                        "original_url": original_url,
                                        "test_url": test_url,
                                        "original_status": resp_orig.status_code,
                                        "test_status": resp_test.status_code,
                                        "owasp": "API1: Broken Object Level Authorization"
                                    },
                                    endpoint=path,
                                    method="GET",
                                    severity="high"
                                ))
                    except:
                        pass

        return findings
