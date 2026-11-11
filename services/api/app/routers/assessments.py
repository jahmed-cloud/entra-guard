import logging
import os
import uuid
from datetime import datetime, timedelta, timezone
from typing import Optional
from celery import Celery
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, ConfigDict
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from app.core.database import get_db
from app.core.audit import audit
from app.models.models import ScanRun, AssessmentDefinition, Target
from app.auth.router import require_auth, require_admin
from app.routers.targets import parse_uuid

log = logging.getLogger(__name__)
router = APIRouter()

# A pending/running scan older than this is treated as dead (worker crashed
# or was restarted mid-scan) and no longer blocks a new one.
SCAN_STALE_MINUTES = int(os.getenv("SCAN_STALE_MINUTES", "60"))

class RunRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    target_id: Optional[uuid.UUID] = None

def get_celery():
    broker = os.getenv("CELERY_BROKER_URL", os.getenv("REDIS_URL", "redis://redis:6379/0"))
    # Previously derived from the broker URL, which produced an invalid
    # "redis://redis:6379/1_backend" with the shipped compose file.
    backend = os.getenv("CELERY_RESULT_BACKEND", broker)
    return Celery("cspm", broker=broker, backend=backend)

@router.post("/assessments/run")
async def run_assessment(req: Optional[RunRequest] = None, db: AsyncSession = Depends(get_db), user=Depends(require_admin)):
    if req and req.target_id:
        result = await db.execute(select(Target).where(Target.id == req.target_id))
        t = result.scalar_one_or_none()
        if not t:
            raise HTTPException(404, "Target not found")
    else:
        result = await db.execute(select(Target).where(Target.is_active == True).limit(1))
        t = result.scalar_one_or_none()
        if not t:
            raise HTTPException(400, "No targets configured")
    target_id = str(t.id)

    # One scan per target at a time. Each scan makes several hundred Graph
    # calls with the tenant's credentials, so letting requests stack up gets
    # the app registration throttled and fills the history with duplicates.
    cutoff = datetime.now(timezone.utc) - timedelta(minutes=SCAN_STALE_MINUTES)
    active = await db.execute(
        select(ScanRun.id).where(ScanRun.target_id == t.id,
                                 ScanRun.status.in_(("pending", "running")),
                                 ScanRun.created_at >= cutoff).limit(1))
    if active.scalar_one_or_none():
        raise HTTPException(409, "A scan is already pending or running for this target. "
                                 f"If it is stuck, it stops blocking new scans after {SCAN_STALE_MINUTES} minutes.")

    run = ScanRun(id=uuid.uuid4(), target_id=target_id, status="pending", triggered_by="api")
    db.add(run)
    await db.commit()
    await db.refresh(run)

    try:
        celery = get_celery()
        celery.send_task("app.tasks.run_assessment_task", args=[str(run.id), target_id])
    except Exception as e:
        # The detail goes to the log and the run record (admins can read it
        # in Scan History), not into the HTTP response.
        log.exception("Failed to queue scan %s", run.id)
        run.status = "failed"
        run.error_message = str(e)[:500]
        await db.commit()
        raise HTTPException(503, "Could not queue the scan. Check that the worker and Redis are running.")

    audit("scan_started", user, run_id=run.id, target_id=target_id)
    return {"id": str(run.id), "status": run.status, "target_id": target_id}

@router.get("/assessments/runs")
async def list_runs(db: AsyncSession = Depends(get_db), user=Depends(require_auth)):
    result = await db.execute(select(ScanRun).order_by(ScanRun.created_at.desc()).limit(50))
    runs = result.scalars().all()
    return {"items": [
        {"id": str(r.id), "target_id": str(r.target_id), "status": r.status,
         "triggered_by": r.triggered_by, "checks_total": r.checks_total,
         "checks_passed": r.checks_passed, "checks_failed": r.checks_failed,
         "ai_summary": r.ai_summary,
         "started_at": r.started_at.isoformat() if r.started_at else None,
         "completed_at": r.completed_at.isoformat() if r.completed_at else None,
         "created_at": r.created_at.isoformat() if r.created_at else None}
        for r in runs
    ]}

@router.get("/assessments/runs/{run_id}")
async def get_run(run_id: str, db: AsyncSession = Depends(get_db), user=Depends(require_auth)):
    result = await db.execute(select(ScanRun).where(ScanRun.id == parse_uuid(run_id, "Run")))
    r = result.scalar_one_or_none()
    if not r:
        raise HTTPException(404, "Run not found")
    return {"id": str(r.id), "target_id": str(r.target_id), "status": r.status,
            "checks_total": r.checks_total, "checks_passed": r.checks_passed,
            "checks_failed": r.checks_failed, "error_message": r.error_message,
            "ai_summary": r.ai_summary,
            "started_at": r.started_at.isoformat() if r.started_at else None,
            "completed_at": r.completed_at.isoformat() if r.completed_at else None}

@router.get("/assessments/definitions")
async def list_definitions(page_size: int = Query(200, ge=1, le=500), db: AsyncSession = Depends(get_db), user=Depends(require_auth)):
    result = await db.execute(select(AssessmentDefinition).where(AssessmentDefinition.is_active == True).limit(page_size))
    defs = result.scalars().all()
    return {"items": [
        {"check_id": d.check_id, "title": d.title, "description": d.description,
         "focus_area": d.focus_area, "technology": d.technology, "severity": d.severity,
         "base_score": float(d.base_score or 0), "effort": d.effort,
         "remediation_steps": d.remediation_steps, "reference_urls": d.reference_urls or [],
         "compliance_mappings": d.compliance_mappings or {}}
        for d in defs
    ]}
