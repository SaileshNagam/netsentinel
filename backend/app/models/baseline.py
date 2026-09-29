"""
NetSentinel Behavioral Baseline Model ("Learn My Network")
"""
from datetime import datetime
from sqlalchemy import Column, String, Integer, Float, Boolean, DateTime, ForeignKey, Text
from sqlalchemy.orm import relationship
from app.core.database import Base

class BehaviorBaseline(Base):
    __tablename__ = "behavior_baselines"

    device_id = Column(String(64), ForeignKey("devices.id", ondelete="CASCADE"), primary_key=True)
    typical_active_hours_mask = Column(String(32), default="111111111111111111111111") # 24-char bitmask for 00:00 - 23:00
    expected_ip_subnets = Column(Text, default='["192.168.1.0/24"]') # JSON string of expected CIDRs
    expected_services = Column(Text, default="[]") # JSON list of ports typically open
    avg_session_duration_sec = Column(Integer, default=3600)
    connection_frequency_per_day = Column(Float, default=1.0)
    is_baseline_locked = Column(Boolean, default=False)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)

    device = relationship("Device", back_populates="baseline")
