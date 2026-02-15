import httpx
from typing import List, Dict
from app.scanner.rules.base import BaseRule
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

    async def run(self, target_url: str, endpoints: List[Dict], config: Dict) -> List[Dict]:
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
                
                # Check if endpoint has parameters (heuristically)
                # In a real scanner, we'd parse parameters from OpenAPI spec
                # Here we just blindly append if it looks like a resource ID
                
                base_url = f"{target_url}{endpoint['path']}"
                
                # Test SQLi
                for p_type, p_list in payloads.items():
                    for payload in p_list:
                        # Construct URL with payload
                        # Assuming we are testing a generic 'q' or 'id' param, or appending to URL
                        # Real implementation needs to parse OpenAPI parameters
                        
                        test_url = base_url
                        if '{' in test_url:
                            # Replace path params with payload
                            # e.g. /users/{id} -> /users/1'
                             # We need to know valid IDs, skipping complex path replacement for this demo
                             pass
                        else:
                            # Try query param injection
                            test_url = f"{base_url}?q={urllib.parse.quote(payload)}"
                            # Also try appending to URL for REST paths like /users/1
                            # test_url_path = f"{base_url}/{urllib.parse.quote(payload)}" 
                        
                        try:
                            response = await client.get(test_url, headers=headers)
                            
                            if p_type == "SQLi":
                                errors = ["syntax error", "mysql", "postgres", "sqlite", "oracle"]
                                if any(e in response.text.lower() for e in errors):
                                    findings.append(self.build_finding(
                                        description=f"Possible SQL Injection detected with payload: {payload}",
                                        details={"url": test_url, "response_snippet": response.text[:200]},
                                        endpoint=endpoint['path'],
                                        method="GET",
                                        severity="high"
                                    ))
                            
                            elif p_type == "XSS":
                                if payload in response.text:
                                    findings.append(self.build_finding(
                                        description=f"Reflected XSS detected with payload: {payload}",
                                        details={"url": test_url},
                                        endpoint=endpoint['path'],
                                        method="GET",
                                        severity="high"
                                    ))
                        except:
                            pass

        return findings
