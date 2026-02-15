from sqlalchemy.orm import Session
from app.models.scan import ScanJob, ScanResult
from datetime import datetime
import asyncio
import httpx
import yaml
import json
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

            for rule in self.rules:
                findings = await rule.run(scan.target_url, endpoints, scan.config or {})
                for finding in findings:
                    result = ScanResult(
                        job_id=self.scan_id,
                        rule_id=finding['rule_id'],
                        severity=finding['severity'],
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
                        availability=finding.get('availability')
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
