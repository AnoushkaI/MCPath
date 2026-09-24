"""SQLAlchemy persistence models for MCPath Zero-Trust Security Proxy.

Tables:
1. servers - Registered and active MCP downstream servers
2. tools - Discovered tools and JSON schemas
3. approved_hashes - Canonical JSON schemas and approved SHA-256 integrity hashes
4. capabilities - Stage 2 capability graph nodes and permissions (placeholder)
5. baseline_traces - Stage 4 behavioral historical traces (placeholder)
6. security_events - Intercepted tool calls, risk scores, and final decisions
7. stage_results - Granular per-stage evaluation logs (Stages 1 - 5)
8. decisions - Deterministic Risk Engine enforcement records
"""

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from sqlalchemy import (
    Column,
    Integer,
    String,
    Float,
    Boolean,
    Text,
    DateTime,
    JSON,
    ForeignKey,
    UniqueConstraint,
    Index,
)
from sqlalchemy.orm import declarative_base, relationship

Base = declarative_base()


class ServerDB(Base):
    """Registered MCP downstream servers."""
    __tablename__ = "servers"

    id = Column(Integer, primary_key=True, autoincrement=True)
    name = Column(String(100), unique=True, nullable=False, index=True)
    command = Column(String(255), nullable=False)
    args = Column(JSON, default=list, nullable=False)
    env_vars = Column(JSON, default=dict, nullable=False)
    is_active = Column(Boolean, default=True, nullable=False)
    trust_status = Column(String(20), default="UNTRUSTED", nullable=False)
    last_discovery_time = Column(DateTime(timezone=True), nullable=True)
    last_trust_time = Column(DateTime(timezone=True), nullable=True)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False)
    updated_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc), nullable=False)

    # Relationships
    tools = relationship("ToolDB", back_populates="server", cascade="all, delete-orphan")


class ToolDB(Base):
    """Discovered MCP tools for each server."""
    __tablename__ = "tools"

    id = Column(Integer, primary_key=True, autoincrement=True)
    server_id = Column(Integer, ForeignKey("servers.id", ondelete="CASCADE"), nullable=False, index=True)
    server_name = Column(String(100), nullable=False, index=True)
    name = Column(String(100), nullable=False, index=True)
    description = Column(Text, nullable=True)
    input_schema = Column(JSON, nullable=False)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False)
    updated_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc), nullable=False)

    __table_args__ = (
        UniqueConstraint("server_id", "name", name="uq_server_tool_name"),
    )

    # Relationships
    server = relationship("ServerDB", back_populates="tools")
    approved_hashes = relationship("ApprovedHashDB", back_populates="tool", cascade="all, delete-orphan")
    capabilities = relationship("CapabilityDB", back_populates="tool", cascade="all, delete-orphan")
    baseline_traces = relationship("BaselineTraceDB", back_populates="tool", cascade="all, delete-orphan")


class ApprovedHashDB(Base):
    """Approved SHA-256 hashes of canonical tool definitions for Stage 1 Integrity Check."""
    __tablename__ = "approved_hashes"

    id = Column(Integer, primary_key=True, autoincrement=True)
    tool_id = Column(Integer, ForeignKey("tools.id", ondelete="CASCADE"), nullable=False, index=True)
    server_name = Column(String(100), nullable=False, index=True)
    tool_name = Column(String(100), nullable=False, index=True)
    canonical_json = Column(Text, nullable=False)
    hash_sha256 = Column(String(64), nullable=False, index=True)
    is_active = Column(Boolean, default=True, nullable=False)
    approved_by = Column(String(100), default="system:initial_discovery", nullable=False)
    approved_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False)
    revoked_at = Column(DateTime(timezone=True), nullable=True)

    # Relationships
    tool = relationship("ToolDB", back_populates="approved_hashes")


class CapabilityDB(Base):
    """Stage 2 Capability Graph node / action mapping."""
    __tablename__ = "capabilities"

    id = Column(Integer, primary_key=True, autoincrement=True)
    tool_id = Column(Integer, ForeignKey("tools.id", ondelete="CASCADE"), nullable=True, index=True)
    tool_name = Column(String(100), nullable=False, index=True)
    server_name = Column(String(100), nullable=True, index=True)
    resource_type = Column(String(100), nullable=True)
    action = Column(String(100), nullable=True)
    operation = Column(String(20), nullable=True)
    destination = Column(String(100), nullable=True)
    data_sensitivity = Column(Float, default=0.0, nullable=False)
    action_sensitivity = Column(Float, default=0.0, nullable=False)
    external_exposure = Column(Float, default=0.0, nullable=False)
    risk_weight = Column(Float, default=0.0, nullable=False)
    policy_version = Column(String(50), default="1.0.0", nullable=False)
    metadata_json = Column(JSON, default=dict, nullable=False)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False)

    # Relationships
    tool = relationship("ToolDB", back_populates="capabilities")


class CapabilityNodeDB(Base):
    """Dynamic capability graph nodes persisted in PostgreSQL."""
    __tablename__ = "capability_nodes"

    id = Column(Integer, primary_key=True, autoincrement=True)
    node_id = Column(String(150), unique=True, nullable=False, index=True)
    node_type = Column(String(50), nullable=False, index=True)
    label = Column(String(150), nullable=False)
    server_name = Column(String(100), nullable=True, index=True)
    attributes_json = Column(JSON, default=dict, nullable=False)
    policy_version = Column(String(50), default="1.0.0", nullable=False)
    updated_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False)


class CapabilityEdgeDB(Base):
    """Dynamic capability graph typed edges persisted in PostgreSQL."""
    __tablename__ = "capability_edges"

    id = Column(Integer, primary_key=True, autoincrement=True)
    source_node = Column(String(150), nullable=False, index=True)
    target_node = Column(String(150), nullable=False, index=True)
    relation = Column(String(50), nullable=False, index=True)
    attributes_json = Column(JSON, default=dict, nullable=False)
    policy_version = Column(String(50), default="1.0.0", nullable=False)
    updated_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False)


class CapabilityPathDB(Base):
    """Enumerated compatible capability paths and scores persisted in PostgreSQL."""
    __tablename__ = "capability_paths"

    id = Column(Integer, primary_key=True, autoincrement=True)
    tool_name = Column(String(100), nullable=False, index=True)
    path_nodes = Column(JSON, nullable=False)
    path_edges = Column(JSON, nullable=False)
    data_sensitivity = Column(Float, nullable=False)
    action_sensitivity = Column(Float, nullable=False)
    external_exposure = Column(Float, nullable=False)
    chain_risk = Column(Float, nullable=False)
    path_risk_score = Column(Float, nullable=False)
    classification = Column(String(20), nullable=False, index=True)
    is_critical_override = Column(Boolean, default=False, nullable=False)
    explanation = Column(Text, nullable=True)
    policy_version = Column(String(50), default="1.0.0", nullable=False)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False)


class BaselineTraceDB(Base):
    """Stage 4 Behavioral baseline traces (placeholder for Day 9)."""
    __tablename__ = "baseline_traces"

    id = Column(Integer, primary_key=True, autoincrement=True)
    tool_id = Column(Integer, ForeignKey("tools.id", ondelete="CASCADE"), nullable=True, index=True)
    tool_name = Column(String(100), nullable=False, index=True)
    trace_data = Column(JSON, nullable=False)
    recorded_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False)

    # Relationships
    tool = relationship("ToolDB", back_populates="baseline_traces")


class SecurityEventDB(Base):
    """Intercepted tool call security event audit log."""
    __tablename__ = "security_events"

    id = Column(Integer, primary_key=True, autoincrement=True)
    event_id = Column(String(64), unique=True, nullable=False, index=True)
    timestamp = Column(String(64), nullable=False, index=True)
    server_name = Column(String(100), nullable=False, index=True)
    tool_name = Column(String(100), nullable=False, index=True)
    arguments_json = Column(JSON, nullable=True)
    user_prompt = Column(Text, nullable=True)

    # Stage 1 Hash Integrity fields
    expected_hash = Column(String(64), nullable=True)
    observed_hash = Column(String(64), nullable=True)
    hash_matched = Column(Boolean, nullable=True)

    # Graded Risk Scores (Stages 2 - 5)
    capability_risk = Column(Float, nullable=True)
    intent_risk = Column(Float, nullable=True)
    behaviour_risk = Column(Float, nullable=True)
    response_risk = Column(Float, nullable=True)

    # Final Enforcement Decision (Stage 6)
    decision = Column(String(20), nullable=False, index=True)  # ALLOW, HOLD, BLOCK
    reason = Column(Text, nullable=False)
    hard_gate_triggered = Column(String(100), nullable=True)
    action_taken = Column(String(100), nullable=False)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False)

    # Relationships
    stage_results = relationship("StageResultDB", back_populates="security_event", cascade="all, delete-orphan")
    decision_record = relationship("DecisionDB", back_populates="security_event", uselist=False, cascade="all, delete-orphan")


class StageResultDB(Base):
    """Granular per-stage evaluation results for each intercepted call."""
    __tablename__ = "stage_results"

    id = Column(Integer, primary_key=True, autoincrement=True)
    event_id = Column(String(64), ForeignKey("security_events.event_id", ondelete="CASCADE"), nullable=False, index=True)
    stage_number = Column(Integer, nullable=False)
    stage_name = Column(String(100), nullable=False)
    passed = Column(Boolean, nullable=False)
    hard_block = Column(Boolean, default=False, nullable=False)
    score = Column(Float, nullable=True)
    explanation = Column(Text, nullable=True)
    metadata_json = Column(JSON, nullable=True)
    evaluated_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False)

    # Relationships
    security_event = relationship("SecurityEventDB", back_populates="stage_results")


class DecisionDB(Base):
    """Deterministic Risk Engine final decision record."""
    __tablename__ = "decisions"

    id = Column(Integer, primary_key=True, autoincrement=True)
    event_id = Column(String(64), ForeignKey("security_events.event_id", ondelete="CASCADE"), unique=True, nullable=False, index=True)
    decision = Column(String(20), nullable=False, index=True)  # ALLOW, HOLD, BLOCK
    reason = Column(Text, nullable=False)
    hard_gate_triggered = Column(String(100), nullable=True)
    action_taken = Column(String(100), nullable=False)
    evaluated_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False)

    # Relationships
    security_event = relationship("SecurityEventDB", back_populates="decision_record")
