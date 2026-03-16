from typing import Optional, List, Dict, Any
from datetime import datetime
from pydantic import BaseModel

class ScanJobBase(BaseModel):
    target_url: str
    spec_url: Optional[str] = None
    config: Dict[str, Any] = {}

class ScanJobCreate(ScanJobBase):
    spec_content: Optional[Dict[str, Any]] = None

class ScanResultBase(BaseModel):
    rule_id: str
    severity: str
    description: str
    details: Optional[Dict[str, Any]] = None
    endpoint: str
    method: str

    # Metadata for PDF
    impact: Optional[str] = "Unknown"
    remediation: Optional[str] = "Unknown"
    proof_of_concept: Optional[str] = ""
    cvss_vector: Optional[str] = ""
    attack_vector: Optional[str] = ""
    attack_complexity: Optional[str] = ""
    privileges_required: Optional[str] = ""
    user_interaction: Optional[str] = ""
    scope: Optional[str] = ""
    confidentiality: Optional[str] = ""
    integrity: Optional[str] = ""
    availability: Optional[str] = ""
    status: Optional[str] = "Open"
    cvss_score: Optional[str] = ""

class ScanResultCreate(ScanResultBase):
    pass

class ScanResultUpdate(BaseModel):
    status: str

class ScanResult(ScanResultBase):
    id: int
    job_id: int

    class Config:
        from_attributes = True

class ScanJobSummary(BaseModel):
    """Lightweight scan summary for list views — no full results payload."""
    id: int
    target_url: str
    spec_url: Optional[str] = None
    status: str
    created_at: datetime
    completed_at: Optional[datetime] = None
    finding_count: int = 0

    class Config:
        from_attributes = True

class ScanJob(ScanJobBase):
    id: int
    status: str
    created_at: datetime
    completed_at: Optional[datetime] = None
    results: List[ScanResult] = []

    class Config:
        from_attributes = True

class DashboardStats(BaseModel):
    total_scans: int
    completed_scans: int
    running_scans: int
    total_findings: int
    open_findings: int
    critical_findings: int
    high_findings: int
    medium_findings: int
    low_findings: int
    info_findings: int
    findings_by_rule: Dict[str, int]
    owasp_counts: Dict[str, int]
