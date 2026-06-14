from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from app.core.database import get_db
from app.models.models import Target
import uuid

router = APIRouter()

@router.get("/targets")
async def list_targets(db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Target).where(Target.is_active == True))
    targets = result.scalars().all()
    return {"items": [
        {"id": str(t.id), "name": t.name, "type": t.type, "config": t.config,
         "is_active": t.is_active, "created_at": t.created_at.isoformat() if t.created_at else None}
        for t in targets
    ]}

@router.post("/targets")
async def create_target(data: dict, db: AsyncSession = Depends(get_db)):
    t = Target(
        id=uuid.uuid4(),
        name=data.get("name", "My Azure Tenant"),
        type=data.get("type", "azure_tenant"),
        config=data.get("config", {}),
        credential_ref=data.get("credential_ref", "env://AZURE"),
    )
    db.add(t)
    await db.commit()
    await db.refresh(t)
    return {"id": str(t.id), "name": t.name, "type": t.type, "config": t.config}

@router.put("/targets/{target_id}")
async def update_target(target_id: str, data: dict, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Target).where(Target.id == target_id))
    t = result.scalar_one_or_none()
    if not t:
        raise HTTPException(404, "Target not found")
    for k, v in data.items():
        setattr(t, k, v)
    await db.commit()
    await db.refresh(t)
    return {"id": str(t.id), "name": t.name, "type": t.type, "config": t.config}

@router.delete("/targets/{target_id}")
async def delete_target(target_id: str, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Target).where(Target.id == target_id))
    t = result.scalar_one_or_none()
    if not t:
        raise HTTPException(404, "Target not found")
    await db.delete(t)
    await db.commit()
    return {"deleted": True}
