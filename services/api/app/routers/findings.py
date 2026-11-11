import uuid
from typing import Optional
from fastapi import APIRouter, Depends, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from app.core.database import get_db
from app.models.models import Finding, ScanRun
from app.auth.router import require_auth
from app.services.impact import compute_impact

router = APIRouter()

# Malformed IDs, unknown statuses and out-of-range paging are rejected with a
# 422 by FastAPI before any query runs.
StatusFilter = Optional[str]
_STATUS_QUERY = Query(None, pattern=r"^(passed|failed|error)$")

async def _resolve_run_id(db: AsyncSession, target_id, scan_run_id):
    """If no scan_run_id is given, use the latest completed run."""
    if scan_run_id:
        return scan_run_id
    run_q = select(ScanRun).where(ScanRun.status == "completed")
    if target_id:
        run_q = run_q.where(ScanRun.target_id == target_id)
    run_q = run_q.order_by(ScanRun.completed_at.desc()).limit(1)
    latest_run = (await db.execute(run_q)).scalar_one_or_none()
    return latest_run.id if latest_run else None

@router.get("/findings")
async def list_findings(
    target_id: Optional[uuid.UUID] = None,
    scan_run_id: Optional[uuid.UUID] = None,
    status: StatusFilter = _STATUS_QUERY,
    page: int = Query(1, ge=1, le=10_000),
    page_size: int = Query(500, ge=1, le=1000),
    db: AsyncSession = Depends(get_db),
    user=Depends(require_auth),
):
    scan_run_id = await _resolve_run_id(db, target_id, scan_run_id)

    q = select(Finding)
    if target_id:
        q = q.where(Finding.target_id == target_id)
    if scan_run_id:
        q = q.where(Finding.scan_run_id == scan_run_id)
    if status:
        q = q.where(Finding.status == status)

    q = q.order_by(Finding.score.desc()).limit(page_size).offset((page - 1) * page_size)
    result = await db.execute(q)
    findings = result.scalars().all()

    return {"items": [
        {
            "id": str(f.id),
            "scan_run_id": str(f.scan_run_id) if f.scan_run_id else None,
            "target_id": str(f.target_id),
            "check_id": f.check_id,
            "status": f.status,
            "severity": f.severity,
            "score": float(f.score or 0),
            "affected_resources": f.affected_resources or [],
            "evidence": f.evidence or {},
            "risk_description": f.risk_description,
            "remediation_steps": f.remediation_steps,
            "estimated_effort": f.estimated_effort,
            "ai_explanation": f.ai_explanation,
            "ai_false_positive_likelihood": f.ai_false_positive_likelihood,
            "ai_false_positive_reason": f.ai_false_positive_reason,
            "ai_queries_made": f.ai_queries_made,
            "first_seen_at": f.first_seen_at.isoformat() if f.first_seen_at else None,
            "last_seen_at": f.last_seen_at.isoformat() if f.last_seen_at else None,
        }
        for f in findings
    ]}

@router.get("/findings/impact")
async def findings_impact(
    target_id: Optional[uuid.UUID] = None,
    scan_run_id: Optional[uuid.UUID] = None,
    top: int = Query(5, ge=1, le=25),
    db: AsyncSession = Depends(get_db),
    user=Depends(require_auth),
):
    """Severity-weighted posture score and the fixes that would raise it most.
    See app/services/impact.py for the model."""
    scan_run_id = await _resolve_run_id(db, target_id, scan_run_id)
    if not scan_run_id:
        return {"scan_run_id": None, **compute_impact([], top)}

    q = select(Finding).where(Finding.scan_run_id == scan_run_id)
    if target_id:
        q = q.where(Finding.target_id == target_id)
    rows = (await db.execute(q)).scalars().all()
    findings = [
        {"check_id": f.check_id, "status": f.status, "severity": f.severity,
         "score": float(f.score or 0), "estimated_effort": f.estimated_effort,
         "affected_resources": f.affected_resources, "evidence": f.evidence,
         "risk_description": f.risk_description}
        for f in rows
    ]
    return {"scan_run_id": str(scan_run_id), **compute_impact(findings, top)}
