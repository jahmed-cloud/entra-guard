import uuid
from datetime import datetime, timezone
from sqlalchemy import Column, String, Boolean, DateTime, Numeric, Integer, Text, ForeignKey
from sqlalchemy.dialects.postgresql import UUID, JSONB, ARRAY
from sqlalchemy.orm import relationship
from app.core.database import Base

def now_utc():
    return datetime.now(timezone.utc)

class Target(Base):
    __tablename__ = "targets"
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name = Column(String, nullable=False)
    type = Column(String, default="azure_tenant")
    config = Column(JSONB, default={})
    credential_ref = Column(String, default="env://AZURE")
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime(timezone=True), default=now_utc)
    updated_at = Column(DateTime(timezone=True), default=now_utc, onupdate=now_utc)
    scan_runs = relationship("ScanRun", back_populates="target", cascade="all, delete-orphan")
    findings = relationship("Finding", back_populates="target", cascade="all, delete-orphan")

class ScanRun(Base):
    __tablename__ = "scan_runs"
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    target_id = Column(UUID(as_uuid=True), ForeignKey("targets.id", ondelete="CASCADE"))
    status = Column(String, default="pending")
    triggered_by = Column(String, default="api")
    checks_total = Column(Integer, default=0)
    checks_passed = Column(Integer, default=0)
    checks_failed = Column(Integer, default=0)
    checks_skipped = Column(Integer, default=0)
    error_message = Column(Text)
    # AI-generated narrative summarising what actually matters from this scan —
    # written once, after all findings are in, from the aggregate results only
    # (severity counts, top findings, false-positive flags already set on
    # individual findings). Never used to compute checks_passed/failed/skipped
    # above; purely descriptive. Null when AI_EXPLAIN_ENABLED=false.
    ai_summary = Column(Text, nullable=True)
    started_at = Column(DateTime(timezone=True))
    completed_at = Column(DateTime(timezone=True))
    created_at = Column(DateTime(timezone=True), default=now_utc)
    updated_at = Column(DateTime(timezone=True), default=now_utc, onupdate=now_utc)
    target = relationship("Target", back_populates="scan_runs")
    findings = relationship("Finding", back_populates="scan_run")

class AssessmentDefinition(Base):
    __tablename__ = "assessment_definitions"
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    check_id = Column(String, unique=True, nullable=False)
    title = Column(String, nullable=False)
    description = Column(Text)
    focus_area = Column(String)
    technology = Column(String, default="AzureAD")
    severity = Column(String, nullable=False)
    base_score = Column(Numeric(4, 1), default=5.0)
    probability = Column(String, default="High")
    impact = Column(String, default="High")
    effort = Column(String, default="Low")
    plugin_module = Column(String)
    remediation_steps = Column(Text)
    reference_urls = Column(ARRAY(Text))
    compliance_mappings = Column(JSONB, default={})
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime(timezone=True), default=now_utc)
    updated_at = Column(DateTime(timezone=True), default=now_utc, onupdate=now_utc)

class Finding(Base):
    __tablename__ = "findings"
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    scan_run_id = Column(UUID(as_uuid=True), ForeignKey("scan_runs.id", ondelete="SET NULL"), nullable=True)
    target_id = Column(UUID(as_uuid=True), ForeignKey("targets.id", ondelete="CASCADE"))
    check_id = Column(String, nullable=False)
    status = Column(String, nullable=False)
    severity = Column(String)
    score = Column(Numeric(4, 1), default=0)
    affected_resources = Column(JSONB, default=[])
    evidence = Column(JSONB, default={})
    risk_description = Column(Text)
    remediation_steps = Column(Text)
    estimated_effort = Column(String, default="Low")
    ai_explanation = Column(Text, nullable=True)
    # Bounded to "none" | "possible" | "likely" — deliberately NOT a boolean.
    # This is the AI's judgment about whether `status` might be wrong given
    # context the deterministic check couldn't see (e.g. MFA enforced via a
    # tenant setting the check doesn't query). It is advisory only — `status`
    # above is never modified by this. See ai_explainer.py's module docstring.
    ai_false_positive_likelihood = Column(String, nullable=True)
    ai_false_positive_reason = Column(Text, nullable=True)
    # Audit trail of Graph API paths the investigative agent queried while
    # verifying this finding, e.g. ["/policies/identitySecurityDefaultsEnforcementPolicy"].
    # Stored as JSON text (not a native array column) to keep the migration
    # simple and consistent with the other JSONB-via-text fields on this
    # model. Null for findings handled by the plain (non-agent) explainer.
    ai_queries_made = Column(Text, nullable=True)
    first_seen_at = Column(DateTime(timezone=True), default=now_utc)
    last_seen_at = Column(DateTime(timezone=True), default=now_utc)
    resolved_at = Column(DateTime(timezone=True))
    created_at = Column(DateTime(timezone=True), default=now_utc)
    updated_at = Column(DateTime(timezone=True), default=now_utc, onupdate=now_utc)
    target = relationship("Target", back_populates="findings")
    scan_run = relationship("ScanRun", back_populates="findings")
