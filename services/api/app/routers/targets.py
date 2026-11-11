import re
import uuid
from typing import Annotated, Any, Literal, Optional
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, ConfigDict, Field, StringConstraints, field_validator
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from app.core.database import get_db
from app.core.audit import audit
from app.models.models import Target
from app.auth.router import require_auth, require_admin

router = APIRouter()

_GUID = r"[0-9a-fA-F]{8}-(?:[0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}"
_GUID_RE = re.compile(rf"^{_GUID}$")
# A tenant is addressed by its GUID or a verified domain (contoso.onmicrosoft.com).
_TENANT_RE = re.compile(rf"^(?:{_GUID}|(?=.{{4,253}}$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{{0,61}}[A-Za-z0-9])?\.)+[A-Za-z]{{2,63}})$")
_CONFIG_KEY_RE = re.compile(r"^[a-z][a-z0-9_]{0,63}$")
_SECRET_KEY_RE = re.compile(r"secret|password|passwd|token|credential|private|api_?key")
_GUID_FIELDS = ("client_id", "break_glass_group_id")

def validate_target_config(config: dict) -> dict:
    """The config is stored as-is, returned to every signed-in user by
    GET /targets, and interpolated into Microsoft login URLs by the worker —
    so it must be small, well-formed and free of secrets."""
    if len(config) > 20:
        raise ValueError("config can have at most 20 keys")
    for key, value in config.items():
        if not _CONFIG_KEY_RE.match(key):
            raise ValueError(f"config key {key!r} must be lowercase letters, digits and underscores")
        if _SECRET_KEY_RE.search(key):
            raise ValueError(f"config key {key!r} looks like a secret. Secrets belong in environment "
                             "variables (AZURE_CLIENT_SECRET), not in the target config, which every signed-in user can read")
        if not (value is None or isinstance(value, (bool, int, float)) or (isinstance(value, str) and len(value) <= 256)):
            raise ValueError(f"config value for {key!r} must be a string (max 256 characters), number or boolean")
    tenant_id = config.get("tenant_id")
    if tenant_id is not None and not (isinstance(tenant_id, str) and _TENANT_RE.match(tenant_id)):
        raise ValueError("config.tenant_id must be a tenant GUID or a domain such as contoso.onmicrosoft.com")
    for field in _GUID_FIELDS:
        value = config.get(field)
        if value not in (None, "") and not (isinstance(value, str) and _GUID_RE.match(value)):
            raise ValueError(f"config.{field} must be a GUID")
    return config

TargetName = Annotated[str, StringConstraints(strip_whitespace=True, min_length=1, max_length=100)]
# Names an environment-variable prefix (env://AZURE -> AZURE_CLIENT_SECRET); never a secret itself.
CredentialRef = Annotated[str, StringConstraints(pattern=r"^env://[A-Z][A-Z0-9_]{0,63}$")]

class TargetCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: TargetName = "My Azure Tenant"
    type: Literal["azure_tenant"] = "azure_tenant"
    config: dict[str, Any] = Field(default_factory=dict)
    credential_ref: CredentialRef = "env://AZURE"

    @field_validator("config")
    @classmethod
    def _check_config(cls, v):
        return validate_target_config(v)

class TargetUpdate(BaseModel):
    # extra="forbid": previously every key in the body was setattr()'d onto
    # the model, so a caller could overwrite id, created_at, or any column.
    model_config = ConfigDict(extra="forbid")
    name: Optional[TargetName] = None
    type: Optional[Literal["azure_tenant"]] = None
    config: Optional[dict[str, Any]] = None
    credential_ref: Optional[CredentialRef] = None
    is_active: Optional[bool] = None

    @field_validator("config")
    @classmethod
    def _check_config(cls, v):
        return validate_target_config(v) if v is not None else v

def parse_uuid(value: str, what: str = "Target") -> uuid.UUID:
    try:
        return uuid.UUID(str(value))
    except (ValueError, TypeError):
        raise HTTPException(404, f"{what} not found")

@router.get("/targets")
async def list_targets(db: AsyncSession = Depends(get_db), user=Depends(require_auth)):
    result = await db.execute(select(Target).where(Target.is_active == True))
    targets = result.scalars().all()
    return {"items": [
        {"id": str(t.id), "name": t.name, "type": t.type, "config": t.config,
         "is_active": t.is_active, "created_at": t.created_at.isoformat() if t.created_at else None}
        for t in targets
    ]}

@router.post("/targets")
async def create_target(req: TargetCreate, db: AsyncSession = Depends(get_db), user=Depends(require_admin)):
    t = Target(id=uuid.uuid4(), name=req.name, type=req.type, config=req.config,
               credential_ref=req.credential_ref)
    db.add(t)
    await db.commit()
    await db.refresh(t)
    audit("target_created", user, target_id=t.id, name=t.name)
    return {"id": str(t.id), "name": t.name, "type": t.type, "config": t.config}

@router.put("/targets/{target_id}")
async def update_target(target_id: str, req: TargetUpdate, db: AsyncSession = Depends(get_db), user=Depends(require_admin)):
    result = await db.execute(select(Target).where(Target.id == parse_uuid(target_id)))
    t = result.scalar_one_or_none()
    if not t:
        raise HTTPException(404, "Target not found")
    changes = {k: v for k, v in req.model_dump(exclude_unset=True).items() if v is not None}
    for k, v in changes.items():
        setattr(t, k, v)
    await db.commit()
    await db.refresh(t)
    audit("target_updated", user, target_id=t.id, changed=",".join(sorted(changes)) or "nothing")
    return {"id": str(t.id), "name": t.name, "type": t.type, "config": t.config}

@router.delete("/targets/{target_id}")
async def delete_target(target_id: str, db: AsyncSession = Depends(get_db), user=Depends(require_admin)):
    result = await db.execute(select(Target).where(Target.id == parse_uuid(target_id)))
    t = result.scalar_one_or_none()
    if not t:
        raise HTTPException(404, "Target not found")
    await db.delete(t)
    await db.commit()
    audit("target_deleted", user, target_id=target_id, name=t.name)
    return {"deleted": True}
