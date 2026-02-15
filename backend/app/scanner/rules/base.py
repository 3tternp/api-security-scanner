from abc import ABC, abstractmethod
from typing import List, Dict, Any

class BaseRule(ABC):
    id: str = "BASE"
    name: str = "Base Rule"
    description: str = "Base rule description"
    severity: str = "info" # high, medium, low, info
    
    # Metadata for PDF Report
    impact: str = "Information only."
    remediation: str = "No action required."
    cvss_vector: str = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N"
    attack_vector: str = "Network"
    attack_complexity: str = "Low"
    privileges_required: str = "None"
    user_interaction: str = "None"
    scope: str = "Unchanged"
    confidentiality: str = "None"
    integrity: str = "None"
    availability: str = "None"

    @abstractmethod
    async def run(self, target_url: str, endpoints: List[Dict], config: Dict) -> List[Dict]:
        """
        Run the rule checks.
        endpoints: List of discovered endpoints from OpenAPI.
        config: Scan configuration (auth tokens, etc).
        Returns: List of findings.
        """
        pass

    def build_finding(self, description: str, details: Dict, endpoint: str, method: str, severity: str = None,
                      impact: str = None, remediation: str = None, proof_of_concept: str = None, cvss_vector: str = None,
                      attack_vector: str = None, attack_complexity: str = None, privileges_required: str = None,
                      user_interaction: str = None, scope: str = None, confidentiality: str = None,
                      integrity: str = None, availability: str = None) -> Dict:
        """Helper to construct a finding with all metadata."""
        return {
            "rule_id": self.id,
            "rule_name": self.name,
            "severity": severity or self.severity,
            "description": description,
            "details": details,
            "endpoint": endpoint,
            "method": method,
            "impact": impact or self.impact,
            "remediation": remediation or self.remediation,
            "proof_of_concept": proof_of_concept or "See details.",
            "cvss_vector": cvss_vector or self.cvss_vector,
            "attack_vector": attack_vector or self.attack_vector,
            "attack_complexity": attack_complexity or self.attack_complexity,
            "privileges_required": privileges_required or self.privileges_required,
            "user_interaction": user_interaction or self.user_interaction,
            "scope": scope or self.scope,
            "confidentiality": confidentiality or self.confidentiality,
            "integrity": integrity or self.integrity,
            "availability": availability or self.availability
        }
