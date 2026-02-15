from typing import Any, List
from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks
from sqlalchemy.orm import Session
from app.api import deps
from app.db.session import get_db
from app.models.scan import ScanJob, ScanResult
from app.models.user import User
from app.schemas.scan import ScanJob as ScanJobSchema, ScanJobCreate, ScanResult as ScanResultSchema
from app.scanner.engine import ScannerEngine

router = APIRouter()

@router.post("/", response_model=ScanJobSchema)
def create_scan(
    *,
    db: Session = Depends(get_db),
    scan_in: ScanJobCreate,
    background_tasks: BackgroundTasks,
    current_user: User = Depends(deps.get_current_active_admin),
) -> Any:
    print(f"[DEBUG] Received scan creation request: {scan_in}")
    try:
        scan = ScanJob(
            target_url=scan_in.target_url,
            spec_url=scan_in.spec_url,
            config=scan_in.config,
            status="pending"
        )
        db.add(scan)
        db.commit()
        db.refresh(scan)
        print(f"[DEBUG] Scan created in DB with ID: {scan.id}")
        
        # Trigger scan in background
        scanner = ScannerEngine(db, scan.id)
        background_tasks.add_task(scanner.run, scan_in.spec_content)
        print(f"[DEBUG] Background task scheduled for scan {scan.id}")
        
        return scan
    except Exception as e:
        print(f"[DEBUG] Error creating scan: {e}")
        raise HTTPException(status_code=500, detail=str(e))

import logging

logger = logging.getLogger(__name__)

@router.get("/", response_model=List[ScanJobSchema])
def read_scans(
    db: Session = Depends(get_db),
    skip: int = 0,
    limit: int = 100,
    current_user: User = Depends(deps.get_current_active_user),
) -> Any:
    logger.info("DEBUG: Entering read_scans")
    try:
        scans = db.query(ScanJob).offset(skip).limit(limit).all()
        logger.info(f"[DEBUG] Retrieved {len(scans)} scans")
        return scans
    except Exception as e:
        logger.error(f"[ERROR] Failed to read scans: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/{scan_id}", response_model=ScanJobSchema)
def read_scan(
    scan_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(deps.get_current_active_user),
) -> Any:
    scan = db.query(ScanJob).filter(ScanJob.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    return scan

@router.get("/{scan_id}/results", response_model=List[ScanResultSchema])
def read_scan_results(
    scan_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(deps.get_current_active_user),
) -> Any:
    logger.info(f"DEBUG: Entering read_scan_results for scan_id {scan_id}")
    try:
        results = db.query(ScanResult).filter(ScanResult.job_id == scan_id).all()
        logger.info(f"[DEBUG] Retrieved {len(results)} results")
        return results
    except Exception as e:
        logger.error(f"[ERROR] Failed to read scan results: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))


@router.delete("/{scan_id}")
def delete_scan(
    scan_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(deps.get_current_active_admin),
) -> Any:
    scan = db.query(ScanJob).filter(ScanJob.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    db.query(ScanResult).filter(ScanResult.job_id == scan_id).delete()
    db.delete(scan)
    db.commit()
    return {"detail": "Scan deleted"}
