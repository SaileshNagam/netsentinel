"""
NetSentinel Incident & Human Decision Model
"""
import enum
from datetime import datetime
from sqlalchemy import Column, String, Integer, DateTime, ForeignKey, Text
from sqlalchemy.orm import relationship
from app.core.database import Base

class IncidentStatus(str, enum.Enum):
    INVESTIGATING = "INVESTIGATING"
    ESCALATED = "ESCALATED"
    RESOLVED = "RESOLVED"
    DISMISSED = "DISMISSED"

class RecommendedAction(str, enum.Enum):
    BLOCK_DEVICE = "BLOCK_DEVICE"
    ISOLATE = "ISOLATE"
    ADD_TO_WATCHLIST = "ADD_TO_WATCHLIST"
    TRUST_DEVICE = "TRUST_DEVICE"
    INVESTIGATE = "INVESTIGATE"
    IGNORE = "IGNORE"

class ActionStatus(str, enum.Enum):
    PENDING_APPROVAL = "PENDING_APPROVAL"
    APPROVED = "APPROVED"
    DENIED = "DENIED"

class Incident(Base):
    __tablename__ = "incidents"

    id = Column(String(64), primary_key=True, index=True) # e.g. NS-2026-001
    device_id = Column(String(64), ForeignKey("devices.id"), nullable=False, index=True)
    title = Column(String(128), nullable=False)
    severity = Column(String(32), default="HIGH")
    status = Column(String(32), default=IncidentStatus.INVESTIGATING.value, index=True)
    recommended_action = Column(String(64), default=RecommendedAction.INVESTIGATE.value)
    action_status = Column(String(32), default=ActionStatus.PENDING_APPROVAL.value)
    summary = Column(Text, nullable=False)
    evidence_package_hash = Column(String(64), nullable=False) # SHA-256
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False, index=True)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)

    device = relationship("Device", back_populates="incidents")
