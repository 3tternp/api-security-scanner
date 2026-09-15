import httpx
import asyncio
import os
import time
from typing import List, Dict
from app.scanner.rules.base import BaseRule

# On a serverless deploy (Vercel), the whole scan now runs inline within one
# request/function invocation with a hard duration ceiling. This rule's
# escalating burst is the single largest contributor to scan time (85 live
# HTTP requests vs. 1-4 for every other rule) — trim it there so a scan has
# a realistic chance of finishing before the platform times the request out.
# Local/Docker deployments (a long-running process, no per-request deadline)
# keep the full burst for stronger signal.
BURST_TIERS = [3, 7] if os.getenv("VERCEL") == "1" else [10, 25, 50]
RATE_LIMIT_HEADER_PREFIXES = ("x-ratelimit", "retry-after")


class RateLimitRule(BaseRule):
    id = "RATE-LIMIT"
    name = "Rate Limiting Check"
    description = "Checks if the API implements rate limiting by sending burst requests."
    severity = "medium"

    impact = "Denial of Service (DoS) or brute-force attacks against sensitive endpoints."
    remediation = "Implement rate limiting middleware (e.g., Nginx limit_req, Redis-based token bucket) to restrict requests per IP/User."
    cvss_vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H"
    availability = "High"

    async def run(self, target_url: str, endpoints: List[Dict], config: Dict, baseline_cache=None) -> List[Dict]:
        findings = []
        if not endpoints:
            return findings

        test_endpoint = next((ep for ep in endpoints if ep['method'] == 'GET'), None)
        if not test_endpoint:
            return findings

        url = f"{target_url}{test_endpoint['path']}"

        headers = {}
        if config.get('auth_header'):
            headers['Authorization'] = config['auth_header']

        saw_rate_limit_headers = False
        any_tier_limited = False
        last_status_codes: List[int] = []
        total_sent = 0
        start_time = time.time()

        async with httpx.AsyncClient(verify=False, headers=headers) as client:
            for tier_size in BURST_TIERS:
                tasks = [client.get(url) for _ in range(tier_size)]
                responses = await asyncio.gather(*tasks, return_exceptions=True)
                total_sent += tier_size

                status_codes = []
                for r in responses:
                    if isinstance(r, httpx.Response):
                        status_codes.append(r.status_code)
                        for header_name in r.headers:
                            if header_name.lower().startswith(RATE_LIMIT_HEADER_PREFIXES):
                                saw_rate_limit_headers = True
                    else:
                        status_codes.append(0)  # Connection error

                last_status_codes = status_codes
                if 429 in status_codes or 503 in status_codes:
                    any_tier_limited = True
                    break

        duration = time.time() - start_time

        if any_tier_limited:
            return findings  # Rate limiting confirmed present — nothing to report.

        signals = ["no_429_across_burst_tiers"]
        if not saw_rate_limit_headers:
            signals.append("no_rate_limit_headers")
        else:
            # Headers advertise a rate-limit policy but it never triggered —
            # weaker signal (could just mean the burst didn't cross the window).
            pass

        findings.append(self.build_finding(
            description=(
                f"Potential lack of rate limiting. Sent {total_sent} requests across "
                f"escalating bursts ({BURST_TIERS}) in {duration:.2f}s without a 429/503 response."
            ),
            details={
                "status_codes": dict((i, last_status_codes.count(i)) for i in set(last_status_codes)),
                "burst_tiers": BURST_TIERS,
                "rate_limit_headers_present": saw_rate_limit_headers,
                "owasp": "API4: Unrestricted Resource Consumption"
            },
            endpoint=test_endpoint['path'],
            method="GET",
            signals=signals,
        ))

        return findings
