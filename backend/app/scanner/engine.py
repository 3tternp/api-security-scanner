from sqlalchemy.orm import Session
from app.models.scan import ScanJob, ScanResult
from datetime import datetime
from typing import Dict, List
import asyncio
import httpx
import re
import yaml
import json
from app.scanner.baseline import BaselineCache
from app.scanner.rules.security_headers import SecurityHeadersRule
from app.scanner.rules.auth_checks import AuthRequiredRule
from app.scanner.rules.rate_limit import RateLimitRule
from app.scanner.rules.injection import InjectionRule
from app.scanner.rules.sensitive_data import SensitiveDataRule
from app.scanner.rules.bola import BolaRule
from app.scanner.rules.openapi_contract import OpenAPIContractRule
from app.scanner.rules.deserialization import DeserializationRule
from app.scanner.rules.fuzzing import FuzzingRule
from app.scanner.rules.business_logic import BusinessLogicRule
from app.scanner.rules.cors_check import CORSCheckRule
from app.scanner.rules.html_injection import HTMLInjectionRule
from app.scanner.rules.jwt_security import JWTSecurityRule
from app.scanner.rules.ssrf_check import SSRFCheckRule
from app.scanner.rules.mass_assignment import MassAssignmentRule
from app.scanner.rules.broken_function_auth import BrokenFunctionAuthRule
from app.scanner.rules.path_traversal import PathTraversalRule
from app.scanner.rules.cookie_security import CookieSecurityRule
from app.scanner.rules.tls_enforcement import TLSEnforcementRule
from app.scanner.rules.fingerprint_headers import FingerprintHeadersRule
from app.scanner.rules.crypto_oracle import CryptoOracleRule

SEVERITY_TIERS = ["critical", "high", "medium", "low", "info"]

# Rule groups that can flag the same underlying issue on the same endpoint —
# when more than one fires on the same (endpoint, method), only the
# highest-confidence finding is kept.
DUPLICATE_RULE_GROUPS = [
    {"AUTH-MISSING", "JWT-001", "BFLA-001"},
]

_CONFIDENCE_RANK = {"high": 3, "medium": 2, "low": 1}


def _downgrade_severity(severity: str) -> str:
    s = (severity or "info").lower()
    if s in SEVERITY_TIERS:
        idx = SEVERITY_TIERS.index(s)
        return SEVERITY_TIERS[min(idx + 1, len(SEVERITY_TIERS) - 1)]
    return s


def _dedup_findings(findings: list) -> list:
    """Drop lower-confidence duplicates when multiple rules in the same
    DUPLICATE_RULE_GROUPS entry flag the same (endpoint, method)."""
    keep = [True] * len(findings)
    for group in DUPLICATE_RULE_GROUPS:
        buckets: Dict[tuple, list] = {}
        for i, f in enumerate(findings):
            if f.get("rule_id") in group:
                key = (f.get("endpoint"), f.get("method"))
                buckets.setdefault(key, []).append(i)
        for idxs in buckets.values():
            if len(idxs) < 2:
                continue
            idxs_sorted = sorted(
                idxs,
                key=lambda i: _CONFIDENCE_RANK.get(findings[i].get("confidence", "medium"), 2),
                reverse=True,
            )
            for i in idxs_sorted[1:]:
                keep[i] = False
    return [f for f, k in zip(findings, keep) if k]


class ScannerEngine:
    def __init__(self, db: Session, scan_id: int):
        self.db = db
        self.scan_id = scan_id
        self.rules = [
            SecurityHeadersRule(),
            AuthRequiredRule(),
            RateLimitRule(),
            InjectionRule(),
            SensitiveDataRule(),
            BolaRule(),
            OpenAPIContractRule(),
            DeserializationRule(),
            FuzzingRule(),
            BusinessLogicRule(),
            CORSCheckRule(),
            HTMLInjectionRule(),
            JWTSecurityRule(),
            SSRFCheckRule(),
            MassAssignmentRule(),
            BrokenFunctionAuthRule(),
            PathTraversalRule(),
            CookieSecurityRule(),
            TLSEnforcementRule(),
            FingerprintHeadersRule(),
            CryptoOracleRule(),
        ]

    async def fetch_spec(self, url: str):
        if url.startswith("http"):
            try:
                async with httpx.AsyncClient(verify=False) as client:
                    resp = await client.get(url)
                    try:
                        return resp.json()
                    except:
                        return yaml.safe_load(resp.text)
            except Exception:
                return None
        else:
            # Local file reading if it's a path
            try:
                with open(url, 'r') as f:
                    content = f.read()
                    try:
                        return json.loads(content)
                    except:
                        return yaml.safe_load(content)
            except Exception:
                return None

        return None

    def parse_endpoints(self, spec: dict):
        # Postman collection (v2.x): identified by a top-level "item" tree
        # instead of an OpenAPI "paths" map.
        if isinstance(spec.get('item'), list):
            return self._parse_postman_items(spec['item'])

        endpoints = []
        paths = spec.get('paths', {})
        for path, methods in paths.items():
            for method, details in methods.items():
                if method.lower() in ['get', 'post', 'put', 'delete', 'patch']:
                    endpoints.append({
                        'path': path,
                        'method': method.upper(),
                        'details': details
                    })
        return endpoints

    def _parse_postman_items(self, items: List[dict]):
        """Recursively flatten a Postman collection's folder/item tree into
        the same {path, method, details} shape parse_endpoints produces for
        OpenAPI, so every rule can consume either source uninformed of which
        format the scan was started from."""
        endpoints = []
        for item in items:
            if isinstance(item.get('item'), list):
                endpoints.extend(self._parse_postman_items(item['item']))
                continue

            request = item.get('request')
            if not isinstance(request, dict):
                continue

            method = str(request.get('method', 'GET')).upper()
            if method not in ('GET', 'POST', 'PUT', 'DELETE', 'PATCH'):
                continue

            url = request.get('url')
            segments = None
            if isinstance(url, dict):
                segments = url.get('path')
            if not segments:
                raw = url.get('raw', '') if isinstance(url, dict) else (url if isinstance(url, str) else '')
                # Strip a leading {{variable}} host or http(s)://host prefix
                # and any query string, leaving just the path segments —
                # template placeholders inside the path (e.g. {{id}}) are
                # kept as-is so rules can target them (see CryptoOracleRule).
                raw = re.sub(r'^\{\{[^}]+\}\}', '', raw)
                raw = re.sub(r'^https?://[^/]+', '', raw)
                raw = raw.split('?')[0]
                segments = [s for s in raw.split('/') if s]

            if not segments:
                continue

            endpoints.append({
                'path': '/' + '/'.join(segments),
                'method': method,
                'details': {
                    'description': item.get('name', ''),
                    # Marks this endpoint as Postman-sourced (not OpenAPI) so
                    # OPENAPI-CONTRACT knows to check Postman's own auth
                    # representation instead of OpenAPI's 'security' field —
                    # otherwise every Postman endpoint reads as unauthenticated.
                    'source': 'postman',
                    'postman_auth': request.get('auth'),
                },
            })
        return endpoints

    async def discover_endpoints(self, target_url: str):
        """Probes common paths to find valid endpoints."""
        common_paths = [
            "/", "/api", "/api/v1", "/health", "/status", 
            "/users", "/users/me", "/login", "/auth/login", "/token",
            "/admin", "/swagger", "/docs", "/redoc",
            "/api/users", "/api/v1/users", "/api/auth/login",
            "/api/scans", "/api/jobs"
        ]
        discovered = []
        
        async with httpx.AsyncClient(verify=False, timeout=5.0) as client:
            tasks = []
            for path in common_paths:
                tasks.append(self._check_path(client, target_url, path))
            
            results = await asyncio.gather(*tasks)
            for res in results:
                if res:
                    discovered.append(res)
        return discovered

    async def _check_path(self, client, base_url, path):
        try:
            url = f"{base_url}{path}"
            resp = await client.head(url)
            if resp.status_code != 404:
                 return {'path': path, 'method': 'GET', 'details': {'description': 'Heuristic discovery'}}
            
            # Fallback to GET if HEAD is not allowed or returns 404 (some APIs return 404 on HEAD but 200/401 on GET)
            if resp.status_code in [404, 405]:
                resp = await client.get(url)
                if resp.status_code != 404:
                     return {'path': path, 'method': 'GET', 'details': {'description': 'Heuristic discovery'}}
        except:
            pass
        return None

    async def run(self, spec_content: dict = None):
        scan = self.db.query(ScanJob).filter(ScanJob.id == self.scan_id).first()
        if not scan:
            return
        
        scan.status = "running"
        self.db.commit()
        
        try:
            endpoints = []
            if spec_content:
                print(f"[DEBUG] Using provided spec content directly")
                endpoints = self.parse_endpoints(spec_content)
            elif scan.spec_url:
                spec = await self.fetch_spec(scan.spec_url)
                if spec:
                    endpoints = self.parse_endpoints(spec)
            
            # If no endpoints found from spec, use heuristic discovery
            if not endpoints:
                endpoints = await self.discover_endpoints(scan.target_url)
            
            # If still no endpoints, add root at least
            if not endpoints:
                 endpoints = [{'path': '/', 'method': 'GET', 'details': {'description': 'Fallback root'}}]

            baseline_cache = BaselineCache(scan.target_url)
            results_per_rule = await asyncio.gather(
                *(
                    rule.run(scan.target_url, endpoints, scan.config or {}, baseline_cache=baseline_cache)
                    for rule in self.rules
                ),
                return_exceptions=True,
            )
            all_findings = []
            for rule, findings in zip(self.rules, results_per_rule):
                if isinstance(findings, Exception):
                    print(f"[WARN] Rule {rule.id} failed: {findings}")
                    continue
                all_findings.extend(findings)

            all_findings = _dedup_findings(all_findings)

            for finding in all_findings:
                confidence = finding.get('confidence', 'medium')
                severity = finding['severity']
                if confidence == 'low':
                    severity = _downgrade_severity(severity)

                result = ScanResult(
                    job_id=self.scan_id,
                    rule_id=finding['rule_id'],
                    severity=severity,
                    description=finding['description'],
                    details=finding['details'],
                    endpoint=finding['endpoint'],
                    method=finding['method'],
                    # Metadata
                    impact=finding.get('impact'),
                    remediation=finding.get('remediation'),
                    proof_of_concept=finding.get('proof_of_concept'),
                    cvss_vector=finding.get('cvss_vector'),
                    attack_vector=finding.get('attack_vector'),
                    attack_complexity=finding.get('attack_complexity'),
                    privileges_required=finding.get('privileges_required'),
                    user_interaction=finding.get('user_interaction'),
                    scope=finding.get('scope'),
                    confidentiality=finding.get('confidentiality'),
                    integrity=finding.get('integrity'),
                    availability=finding.get('availability'),
                    confidence=confidence,
                    signals=finding.get('signals', []),
                )
                self.db.add(result)
            
            scan.status = "completed"
            scan.completed_at = datetime.utcnow()
            self.db.commit()
        except Exception as e:
            scan.status = "failed"
            scan.completed_at = datetime.utcnow()
            self.db.commit()
            print(f"Scan failed: {e}")
