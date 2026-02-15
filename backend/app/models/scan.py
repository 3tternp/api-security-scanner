from sqlalchemy import Column, Integer, String, JSON, DateTime, ForeignKey, Text
from sqlalchemy.orm import relationship
from datetime import datetime
from app.db.session import Base

class ScanJob(Base):
    __tablename__ = "scan_jobs"

    id = Column(Integer, primary_key=True, index=True)
    target_url = Column(String) # Base URL for the API
    spec_url = Column(String, nullable=True) # URL or path to local file
    status = Column(String, default="pending") # pending, running, completed, failed
    created_at = Column(DateTime, default=datetime.utcnow)
    completed_at = Column(DateTime, nullable=True)
    config = Column(JSON, default={}) # Auth tokens, specific rules to run
    
    # Relationships
    results = relationship("ScanResult", back_populates="job")

class ScanResult(Base):
    __tablename__ = "scan_results"

    id = Column(Integer, primary_key=True, index=True)
    job_id = Column(Integer, ForeignKey("scan_jobs.id"))
    rule_id = Column(String)
    severity = Column(String) # high, medium, low, info
    description = Column(String)
    details = Column(JSON) # evidence, request/response
    endpoint = Column(String)
    method = Column(String)
    
    # Metadata for PDF
    impact = Column(String, default="Unknown")
    remediation = Column(Text, default="Unknown")
    proof_of_concept = Column(Text, default="")
    cvss_vector = Column(String, default="")
    attack_vector = Column(String, default="")
    attack_complexity = Column(String, default="")
    privileges_required = Column(String, default="")
    user_interaction = Column(String, default="")
    scope = Column(String, default="")
    confidentiality = Column(String, default="")
    integrity = Column(String, default="")
    availability = Column(String, default="")

    job = relationship("ScanJob", back_populates="results")
