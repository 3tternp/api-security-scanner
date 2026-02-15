import json
from typing import List, Dict
from app.scanner.rules.base import BaseRule

class OpenAPIContractRule(BaseRule):
    id = "OPENAPI-CONTRACT"
    name = "OpenAPI Contract Security Review"
    description = "Static analysis of OpenAPI definition for security gaps (Auth, PII, File Uploads)."
    severity = "high"
    
    # Default metadata (will be overridden per finding)
    impact = "Varies by issue."
    remediation = "Update OpenAPI definition and implementation."

    async def run(self, target_url: str, endpoints: List[Dict], config: Dict) -> List[Dict]:
        findings = []

        for endpoint in endpoints:
            path = endpoint['path']
            method = endpoint['method']
            details = endpoint.get('details', {})
            
            # Skip if no details (heuristic discovery)
            if not details or details.get('description') == 'Heuristic discovery':
                continue

            if method in ['POST', 'PUT', 'DELETE']:
                if 'security' not in details:
                    poc_data = {
                        "path": path,
                        "method": method,
                        "security": "UNDEFINED"
                    }
                    if 'operationId' in details:
                        poc_data['operationId'] = details['operationId']
                    
                    findings.append(self.build_finding(
                        description="Missing Authentication & Authorization Controls in API Contract",
                        details={
                            "explanation": "Endpoint does not define 'security' requirements. Potential unauthenticated access or broken authorization. (OWASP API2: Broken Authentication, API1: BOLA)",
                            "issue": "Endpoint does not define 'security' requirements.",
                            "risk": "Potential unauthenticated access or broken authorization.",
                            "owasp": "API2: Broken Authentication, API1: BOLA"
                        },
                        endpoint=path,
                        method=method,
                        severity="critical",
                        impact="Unauthorized access could enable account takeover, fraud, or data leakage.",
                        remediation="Enforce strong authentication (OAuth2/JWT) and define 'security' schemes in OpenAPI.",
                        proof_of_concept=json.dumps(poc_data, indent=2),
                        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                        confidentiality="High",
                        integrity="High",
                        availability="Medium"
                    ))

            # Check 2: Unrestricted File Upload (API8/API3)
            request_body = details.get('requestBody', {})
            content = request_body.get('content', {})
            if 'multipart/form-data' in content:
                schema = content['multipart/form-data'].get('schema', {})
                properties = schema.get('properties', {})
                
                # Check for binary/file fields without strict constraints
                for prop_name, prop_def in properties.items():
                    if prop_def.get('type') == 'string' and prop_def.get('format') in ['binary', 'byte']:
                        # Generate Proof of Concept (Schema snippet)
                        poc_data = {
                            "field": prop_name,
                            "type": prop_def.get('type'),
                            "format": prop_def.get('format'),
                            "missing_constraints": ["maxLength", "pattern", "contentMediaType"]
                        }

                        findings.append(self.build_finding(
                            description="Unrestricted File Upload Surface (Potential)",
                            details={
                                "explanation": f"Endpoint accepts file upload ({prop_name}) without visible size/type constraints in contract. Malware upload, storage exhaustion, RCE. (OWASP API8: Security Misconfiguration)",
                                "issue": f"Endpoint accepts file upload ({prop_name}) without visible size/type constraints in contract.",
                                "risk": "Malware upload, storage exhaustion, RCE.",
                                "owasp": "API8: Security Misconfiguration"
                            },
                            endpoint=path,
                            method=method,
                            severity="high",
                            impact="Malware storage/distribution, service disruption, or server compromise.",
                            remediation="Strictly validate file types, size, and content. Store outside web root.",
                            proof_of_concept=json.dumps(poc_data, indent=2),
                            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:L/I:H/A:H",
                            confidentiality="Medium",
                            integrity="High",
                            availability="High"
                        ))

            # Check 3: Sensitive PII Exposure (API3/API9)
            # Check request parameters and response schemas for PII keywords
            pii_keywords = ['ssn', 'socialsecurity', 'passport', 'idnumber', 'citizenship', 'dob', 'birthdate', 'phone', 'mobile', 'creditcard', 'cardnumber']
            
            # Check Request Body properties
            if 'content' in request_body:
                for content_type, media in request_body['content'].items():
                    schema = media.get('schema', {})
                    self._check_schema_for_pii(schema, pii_keywords, path, method, findings, "Request Body")

            responses = details.get('responses', {})
            for status_code, response_def in responses.items():
                response_content = response_def.get('content', {})
                for content_type, media in response_content.items():
                    schema = media.get('schema', {})
                    self._check_schema_for_pii(schema, pii_keywords, path, method, findings, f"Response {status_code}")

        return findings

    def _check_schema_for_pii(self, schema, keywords, path, method, findings, location):
        properties = schema.get('properties', {})
        for prop_name, prop_def in properties.items():
            lower_name = prop_name.lower()
            if any(k in lower_name for k in keywords):
                # Generate Proof of Concept
                poc_data = {
                    "field": prop_name,
                    "location": location,
                    "schema_snippet": str(prop_def)
                }

                findings.append(self.build_finding(
                    description="High-Risk PII/Identity Data Handling",
                    details={
                        "explanation": f"Sensitive PII field '{prop_name}' detected in {location}. Data leakage, privacy violation, regulatory non-compliance. (OWASP API3: Broken Object Property Level Authorization)",
                        "issue": f"Sensitive PII field '{prop_name}' detected in {location}.",
                        "risk": "Data leakage, privacy violation, regulatory non-compliance.",
                        "owasp": "API3: Broken Object Property Level Authorization"
                    },
                    endpoint=path,
                    method=method,
                    severity="medium",
                    impact="Potential for identity theft or privacy regulation (GDPR/CCPA) violations.",
                    remediation="Ensure PII is encrypted, masked, or not exposed unnecessarily. Verify authorization.",
                    proof_of_concept=json.dumps(poc_data, indent=2),
                    cvss_vector="CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",
                    confidentiality="High",
                    integrity="None",
                    availability="None"
                ))
