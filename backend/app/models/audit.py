"""
NetSentinel Audit Event Log Model
"""
from datetime import datetime
from sqlalchemy import Column, Integer, String, DateTime, Text
from app.core.database import Base

class AuditEvent(Base):
    __tablename__ = "audit_events"

    id = Column(Integer, primary_key=True, autoincrement=True)
    action = Column(String(64), nullable=False, index=True) # CLASSIFY_DEVICE, ACTION_APPROVE, BASELINE_CLEAR
    actor = Column(String(64), default="LOCAL_ADMIN")
    target_resource = Column(String(128), nullable=False)
    details = Column(Text, nullable=False)
    timestamp = Column(DateTime, default=datetime.utcnow, nullable=False, index=True)
    event_hash = Column(String(64), nullable=False) # SHA-256 for audit tamper resistance
