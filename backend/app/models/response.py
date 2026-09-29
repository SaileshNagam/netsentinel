"""
NetSentinel Defensive Action & Blocklist Models
Models for the human-in-the-loop defensive response pipeline.
"""
import enum
from datetime import datetime, timezone
from sqlalchemy import Column, String, Integer, Boolean, DateTime, Text, ForeignKey, Index
from sqlalchemy.orm import relationship
from app.core.database import Base


def utc_now():
    return datetime.now(timezone.utc)


class ActionType(str, enum.Enum):
    BLOCK_IP = "BLOCK_IP"
    KILL_PROCESS = "KILL_PROCESS"
    TEMPORARY_BLOCKLIST = "TEMPORARY_BLOCKLIST"
    MARK_SUSPICIOUS = "MARK_SUSPICIOUS"
    MONITOR_ONLY = "MONITOR_ONLY"


class ActionStatus(str, enum.Enum):
    REQUESTED = "REQUESTED"
    PENDING_APPROVAL = "PENDING_APPROVAL"
    APPROVED = "APPROVED"
    REJECTED = "REJECTED"
    SIMULATED = "SIMULATED"
    EXECUTED = "EXECUTED"
    FAILED = "FAILED"


class DefensiveAction(Base):
    """
    Represents a defensive action recommended by the Security Agent.
    Follows: REQUESTED → PENDING_APPROVAL → APPROVED/REJECTED → SIMULATED/EXECUTED → AUDITED
    """
    __tablename__ = "defensive_actions"

    id = Column(Integer, primary_key=True, autoincrement=True)
    incident_id = Column(String(64), nullable=True, index=True)      # Links to incidents.id
    action_type = Column(String(32), nullable=False, index=True)     # ActionType enum
    target = Column(String(256), nullable=False)                     # IP, PID, or device ID
    target_details = Column(Text, nullable=True)                     # JSON with extra context
    status = Column(String(32), default=ActionStatus.PENDING_APPROVAL.value, index=True)
    operator = Column(String(64), default="SYSTEM", nullable=False)
    reason = Column(Text, nullable=True)                             # Human-readable rationale
    simulation_mode = Column(Boolean, default=True, nullable=False)  # ALWAYS True by default
    dry_run_result = Column(Text, nullable=True)                     # What would have happened
    execution_result = Column(Text, nullable=True)                   # Actual result if executed
    created_at = Column(DateTime, default=utc_now, nullable=False, index=True)
    decided_at = Column(DateTime, nullable=True)
    executed_at = Column(DateTime, nullable=True)
    audit_hash = Column(String(64), nullable=True)                   # SHA-256 tamper check

    __table_args__ = (
        Index("ix_da_status_ts", "status", "created_at"),
    )


class BlocklistEntry(Base):
    """
    In-memory + persistent TTL-based IP blocklist.
    Entries automatically expire after expires_at.
    """
    __tablename__ = "blocklist_entries"

    id = Column(Integer, primary_key=True, autoincrement=True)
    ip = Column(String(64), nullable=False, unique=True, index=True)
    reason = Column(Text, nullable=True)
    incident_id = Column(String(64), nullable=True, index=True)
    action_id = Column(Integer, nullable=True)
    operator = Column(String(64), default="SYSTEM", nullable=False)
    simulation = Column(Boolean, default=True, nullable=False)       # Is this a real block or simulated?
    created_at = Column(DateTime, default=utc_now, nullable=False)
    expires_at = Column(DateTime, nullable=True, index=True)         # NULL = permanent

    __table_args__ = (
        Index("ix_bl_ip_expires", "ip", "expires_at"),
    )


class InvestigationStage(Base):
    """
    Records each stage of the 6-stage agentic reasoning chain per incident.
    Observe → Analyze → Investigate → Decide → Respond → Report
    """
    __tablename__ = "investigation_stages"

    id = Column(Integer, primary_key=True, autoincrement=True)
    incident_id = Column(String(64), nullable=False, index=True)
    stage = Column(String(32), nullable=False, index=True)           # OBSERVE, ANALYZE, INVESTIGATE, DECIDE, RESPOND, REPORT
    status = Column(String(16), default="PENDING")                  # PENDING, RUNNING, COMPLETE, ERROR
    evidence_json = Column(Text, nullable=True)                      # JSON blob with raw evidence
    narrative = Column(Text, nullable=True)                          # Human-readable stage explanation
    created_at = Column(DateTime, default=utc_now, nullable=False, index=True)
    completed_at = Column(DateTime, nullable=True)

    __table_args__ = (
        Index("ix_is_incident_stage", "incident_id", "stage"),
    )
