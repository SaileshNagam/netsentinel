"""
NetSentinel Security Alerts Model
"""
import enum
from datetime import datetime
from sqlalchemy import Column, String, Integer, DateTime, ForeignKey, Text
from sqlalchemy.orm import relationship
from app.core.database import Base

class AlertStatus(str, enum.Enum):
    ACTIVE = "ACTIVE"
    ACKNOWLEDGED = "ACKNOWLEDGED"
    RESOLVED = "RESOLVED"
    IGNORED = "IGNORED"

class Alert(Base):
    __tablename__ = "alerts"

    id = Column(String(64), primary_key=True, index=True) # UUID
    device_id = Column(String(64), ForeignKey("devices.id", ondelete="SET NULL"), nullable=True, index=True)
    rule_id = Column(String(64), nullable=False, index=True)
    title = Column(String(128), nullable=False)
    description = Column(Text, nullable=False)
    severity = Column(String(32), default="MEDIUM", index=True) # LOW, MEDIUM, HIGH, CRITICAL
    status = Column(String(32), default=AlertStatus.ACTIVE.value, index=True)
    confidence = Column(String(32), default="HIGH")
    evidence_data = Column(Text, default="{}") # JSON blob with detector inputs and values
    deduplication_hash = Column(String(64), nullable=False, index=True) # SHA-256 for cooldown
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False, index=True)
    acknowledged_at = Column(DateTime, nullable=True)
    resolved_at = Column(DateTime, nullable=True)

    device = relationship("Device", back_populates="alerts")
