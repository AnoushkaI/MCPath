"""SQLAlchemy persistence models for MCPath security evidence and state."""

from datetime import datetime, timezone
from typing import Optional
from sqlalchemy import Column, Integer, String, Float, Boolean, Text, DateTime, JSON
from sqlalchemy.orm import declarative_base

Base = declarative_base()


class ToolDefinitionDB(Base):
    """Stores discovered tool definitions, canonical schemas, and approved SHA-256 hashes."""
    __tablename__ = "tool_definitions"

    id = Column(Integer, primary_key=True, autoincrement=True)
    server_name = Column(String(100), nullable=False, index=True)
    tool_name = Column(String(100), nullable=False, index=True)
    schema_json = Column(JSON, nullable=False)
    approved_hash = Column(String(64), nullable=False)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    updated_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))


class SecurityEventDB(Base):
    """Stores every intercepted call, per-stage scores, decisions, and evidence."""
    __tablename__ = "security_events"

    id = Column(Integer, primary_key=True, autoincrement=True)
    event_id = Column(String(64), unique=True, nullable=False, index=True)
    timestamp = Column(String(64), nullable=False, index=True)
    server_name = Column(String(100), nullable=False)
    tool_name = Column(String(100), nullable=False, index=True)
    arguments_json = Column(JSON, nullable=True)
    user_prompt = Column(Text, nullable=True)

    # Hash verification
    expected_hash = Column(String(64), nullable=True)
    observed_hash = Column(String(64), nullable=True)
    hash_matched = Column(Boolean, nullable=True)

    # Graded scores (Stages 2 - 5)
    capability_risk = Column(Float, nullable=True)
    intent_risk = Column(Float, nullable=True)
    behaviour_risk = Column(Float, nullable=True)
    response_risk = Column(Float, nullable=True)

    # Risk Engine decision & explanation (Stage 6)
    decision = Column(String(20), nullable=False, index=True)  # ALLOW, HOLD, BLOCK
    reason = Column(Text, nullable=False)
    hard_gate_triggered = Column(String(100), nullable=True)
    action_taken = Column(String(100), nullable=False)


class BaselineTraceDB(Base):
    """Stores known-good execution traces for Stage 4 behavioural comparison."""
    __tablename__ = "baseline_traces"

    id = Column(Integer, primary_key=True, autoincrement=True)
    tool_name = Column(String(100), nullable=False, index=True)
    trace_json = Column(JSON, nullable=False)
    recorded_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
