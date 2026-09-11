import asyncio
from abc import ABC, abstractmethod
from typing import List, Dict, Any, Optional

from app.scanner.signals import confidence_from_signals


async def bounded_gather(coros, limit: int = 15):
    """Run coroutines concurrently, capped at `limit` in flight at once.

    Rules that probe many (payload x parameter) combinations against the
    same endpoint used to await them one at a time, which turned a scan
    into thousands of serial round-trips. This caps concurrency instead of
    removing it entirely, so we don't flood the target with everything at
    once.
    """
    semaphore = asyncio.Semaphore(limit)

    async def _run(coro):
        async with semaphore:
            return await coro

    return await asyncio.gather(*(_run(c) for c in coros), return_exceptions=True)


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
    async def run(self, target_url: str, endpoints: List[Dict], config: Dict, baseline_cache=None) -> List[Dict]:
        """
        Run the rule checks.
        endpoints: List of discovered endpoints from OpenAPI.
        config: Scan configuration (auth tokens, etc).
        baseline_cache: optional BaselineCache (app.scanner.baseline) shared across
            rules for the current scan, used to diff probe responses against a
            benign baseline instead of hardcoding absolute thresholds.
        Returns: List of findings.
        """
        pass

    def build_finding(self, description: str, details: Dict, endpoint: str, method: str, severity: str = None,
                      impact: str = None, remediation: str = None, proof_of_concept: str = None, cvss_vector: str = None,
                      attack_vector: str = None, attack_complexity: str = None, privileges_required: str = None,
                      user_interaction: str = None, scope: str = None, confidentiality: str = None,
                      integrity: str = None, availability: str = None,
                      signals: Optional[List[str]] = None, confidence: Optional[str] = None) -> Dict:
        """Helper to construct a finding with all metadata.

        signals: list of corroborating-signal names that fired for this finding.
            When provided (and confidence isn't given explicitly), confidence is
            derived from the number of signals via confidence_from_signals().
        """
        signals = signals or []
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
            "availability": availability or self.availability,
            "signals": signals,
            "confidence": confidence or (confidence_from_signals(signals) if signals else "medium"),
        }
