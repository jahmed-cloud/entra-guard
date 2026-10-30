from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, text
from app.core.database import get_db
from app.models.models import Finding, ScanRun
from app.auth.router import require_auth
from app.routers.targets import parse_uuid

router = APIRouter()

@router.get("/findings")
async def list_findings(
    target_id: str = None,
    scan_run_id: str = None,
    status: str = None,
    page: int = 1,
    page_size: int = 500,
    db: AsyncSession = Depends(get_db),
    user=Depends(require_auth),
):
    target_id = parse_uuid(target_id) if target_id else None
    scan_run_id = parse_uuid(scan_run_id, "Run") if scan_run_id else None
    page, page_size = max(page, 1), min(max(page_size, 1), 1000)

    # If no scan_run_id specified, automatically use the latest completed run
    if not scan_run_id:
        run_q = select(ScanRun).where(ScanRun.status == "completed")
        if target_id:
            run_q = run_q.where(ScanRun.target_id == target_id)
        run_q = run_q.order_by(ScanRun.completed_at.desc()).limit(1)
        run_result = await db.execute(run_q)
        latest_run = run_result.scalar_one_or_none()
        if latest_run:
            scan_run_id = latest_run.id

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
