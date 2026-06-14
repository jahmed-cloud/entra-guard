from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from app.core.database import get_db
from app.models.models import ScanRun, AssessmentDefinition, Target
import uuid, os
from celery import Celery

router = APIRouter()

def get_celery():
    broker = os.getenv("CELERY_BROKER_URL", os.getenv("REDIS_URL", "redis://redis:6379/0"))
    backend = broker.replace("/0", "/1") if broker.endswith("/0") else broker + "_backend"
    return Celery("cspm", broker=broker, backend=backend)

@router.post("/assessments/run")
async def run_assessment(data: dict, db: AsyncSession = Depends(get_db)):
    target_id = data.get("target_id")
    if not target_id:
        result = await db.execute(select(Target).limit(1))
        t = result.scalar_one_or_none()
        if not t:
            raise HTTPException(400, "No targets configured")
        target_id = str(t.id)

    run = ScanRun(id=uuid.uuid4(), target_id=target_id, status="pending", triggered_by="api")
    db.add(run)
    await db.commit()
    await db.refresh(run)

    try:
        celery = get_celery()
        celery.send_task("app.tasks.run_assessment_task", args=[str(run.id), target_id])
    except Exception as e:
        run.status = "failed"
        run.error_message = str(e)
        await db.commit()
        raise HTTPException(500, f"Failed to queue scan: {e}")

    return {"id": str(run.id), "status": run.status, "target_id": target_id}

@router.get("/assessments/runs")
async def list_runs(db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(ScanRun).order_by(ScanRun.created_at.desc()).limit(50))
    runs = result.scalars().all()
    return {"items": [
        {"id": str(r.id), "target_id": str(r.target_id), "status": r.status,
         "triggered_by": r.triggered_by, "checks_total": r.checks_total,
         "checks_passed": r.checks_passed, "checks_failed": r.checks_failed,
         "started_at": r.started_at.isoformat() if r.started_at else None,
         "completed_at": r.completed_at.isoformat() if r.completed_at else None,
         "created_at": r.created_at.isoformat() if r.created_at else None}
        for r in runs
    ]}

@router.get("/assessments/runs/{run_id}")
async def get_run(run_id: str, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(ScanRun).where(ScanRun.id == run_id))
    r = result.scalar_one_or_none()
    if not r:
        raise HTTPException(404, "Run not found")
    return {"id": str(r.id), "target_id": str(r.target_id), "status": r.status,
            "checks_total": r.checks_total, "checks_passed": r.checks_passed,
            "checks_failed": r.checks_failed, "error_message": r.error_message,
            "started_at": r.started_at.isoformat() if r.started_at else None,
            "completed_at": r.completed_at.isoformat() if r.completed_at else None}

@router.get("/assessments/definitions")
async def list_definitions(page_size: int = 200, db: AsyncSession = Depends(get_db)):
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
