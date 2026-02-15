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
    details: Dict[str, Any]
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

class ScanResultCreate(ScanResultBase):
    pass

class ScanResult(ScanResultBase):
    id: int
    job_id: int

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
