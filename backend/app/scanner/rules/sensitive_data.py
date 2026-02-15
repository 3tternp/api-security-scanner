import httpx
import re
from typing import List, Dict
from app.scanner.rules.base import BaseRule

class SensitiveDataRule(BaseRule):
    id = "SENSITIVE-DATA"
    name = "Sensitive Data Exposure"
    description = "Checks for sensitive information (PII, secrets) in API responses."
    severity = "high"
    
    impact = "Loss of confidentiality, identity theft, or compromise of backend systems (if keys leaked)."
    remediation = "Ensure sensitive data is not returned in API responses. Use PII masking. Store secrets securely."
    cvss_vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"
    confidentiality = "High"

    async def run(self, target_url: str, endpoints: List[Dict], config: Dict) -> List[Dict]:
        findings = []
        
        # Regex patterns for sensitive data
        patterns = {
            "Email": r'[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+',
            "SSN (US)": r'\b\d{3}-\d{2}-\d{4}\b',
            "API Key": r'(?i)(api_key|apikey|secret|token)["\']?\s*[:=]\s*["\']?[a-zA-Z0-9]{16,}["\']?',
            # "Credit Card": r'\b(?:\d[ -]*?){13,16}\b' # Too many false positives often
        }

        async with httpx.AsyncClient(verify=False) as client:
            headers = {}
            if config.get('auth_header'):
                headers['Authorization'] = config['auth_header']

            for endpoint in endpoints:
                if endpoint['method'] != 'GET':
                    continue
                
                url = f"{target_url}{endpoint['path']}"
                try:
                    response = await client.get(url, headers=headers)
                    text = response.text
                    
                    for p_name, p_regex in patterns.items():
                        matches = re.findall(p_regex, text)
                        if matches:
                            # Filter out own user email if known?
                            # For now just report any finding
                            findings.append(self.build_finding(
                                description=f"Potential {p_name} exposure in response.",
                                details={"count": len(matches), "snippet": str(matches[:3])},
                                endpoint=endpoint['path'],
                                method="GET",
                                severity="medium"
                            ))
                except:
                    pass

        return findings
