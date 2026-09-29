"""
NetSentinel Explainable Risk Score History Model
"""
from datetime import datetime
from sqlalchemy import Column, Integer, String, DateTime, ForeignKey, Text
from sqlalchemy.orm import relationship
from app.core.database import Base

class RiskScoreLog(Base):
    __tablename__ = "risk_scores"

    id = Column(Integer, primary_key=True, autoincrement=True)
    device_id = Column(String(64), ForeignKey("devices.id", ondelete="CASCADE"), nullable=False, index=True)
    score = Column(Integer, nullable=False) # 0 - 100
    severity = Column(String(32), nullable=False) # LOW, MEDIUM, HIGH, CRITICAL
    factors_json = Column(Text, nullable=False) # JSON array of { rule, delta, reason, evidence }
    calculated_at = Column(DateTime, default=datetime.utcnow, nullable=False, index=True)

    device = relationship("Device", back_populates="risk_history")
