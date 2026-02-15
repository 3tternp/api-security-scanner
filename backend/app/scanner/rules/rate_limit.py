import httpx
import asyncio
import time
from typing import List, Dict
from app.scanner.rules.base import BaseRule

class RateLimitRule(BaseRule):
    id = "RATE-LIMIT"
    name = "Rate Limiting Check"
    description = "Checks if the API implements rate limiting by sending burst requests."
    severity = "medium"
    
    impact = "Denial of Service (DoS) or brute-force attacks against sensitive endpoints."
    remediation = "Implement rate limiting middleware (e.g., Nginx limit_req, Redis-based token bucket) to restrict requests per IP/User."
    cvss_vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H"
    availability = "High"

    async def run(self, target_url: str, endpoints: List[Dict], config: Dict) -> List[Dict]:
        findings = []
        if not endpoints:
            return findings

        # Pick a safe GET endpoint to test, preferably one that doesn't modify state
        test_endpoint = None
        for ep in endpoints:
            if ep['method'] == 'GET':
                test_endpoint = ep
                break
        
        if not test_endpoint:
            return findings

        url = f"{target_url}{test_endpoint['path']}"
        request_count = 50
        start_time = time.time()
        
        headers = {}
        if config.get('auth_header'):
            headers['Authorization'] = config['auth_header']

        async with httpx.AsyncClient(verify=False, headers=headers) as client:
            tasks = []
            for _ in range(request_count):
                tasks.append(client.get(url))
            
            responses = await asyncio.gather(*tasks, return_exceptions=True)
            
            status_codes = []
            for r in responses:
                if isinstance(r, httpx.Response):
                    status_codes.append(r.status_code)
                else:
                    status_codes.append(0) # Connection error
            
            # Check for 429 Too Many Requests
            if 429 in status_codes:
                # Rate limiting is present, which is good.
                pass 
            elif status_codes.count(200) == request_count:
                # All requests succeeded instantly - potential lack of rate limiting
                duration = time.time() - start_time
                if duration < 2: # 50 requests in under 2 seconds is quite fast/unrestricted
                    findings.append(self.build_finding(
                        description=f"Potential lack of rate limiting. Sent {request_count} requests in {duration:.2f}s without 429 response.",
                        details={"status_codes": dict((i, status_codes.count(i)) for i in set(status_codes))},
                        endpoint=test_endpoint['path'],
                        method="GET"
                    ))

        return findings
