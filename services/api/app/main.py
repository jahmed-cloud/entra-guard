from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from contextlib import asynccontextmanager
from app.core.database import engine, Base, AsyncSessionLocal
from app.routers import targets, assessments, findings
import os, uuid

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Create tables
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    # Auto-create target from env vars if none exists
    async with AsyncSessionLocal() as db:
        from sqlalchemy import select
        from app.models.models import Target
        result = await db.execute(select(Target).limit(1))
        if not result.scalar_one_or_none():
            tenant_id = os.getenv("AZURE_TENANT_ID") or os.getenv("ENTRA_TENANT_ID")
            client_id = os.getenv("AZURE_CLIENT_ID") or os.getenv("ENTRA_CLIENT_ID")
            if tenant_id and client_id:
                t = Target(
                    id=uuid.uuid4(),
                    name=os.getenv("TARGET_NAME", "My Azure Tenant"),
                    type="azure_tenant",
                    config={"tenant_id": tenant_id, "client_id": client_id},
                    credential_ref="env://AZURE",
                )
                db.add(t)
                await db.commit()

    yield

app = FastAPI(title="EntraGuard API", version="1.0.0", lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(targets.router, prefix="/api/v1")
app.include_router(assessments.router, prefix="/api/v1")
app.include_router(findings.router, prefix="/api/v1")

@app.get("/health")
async def health():
    return {"status": "ok"}
