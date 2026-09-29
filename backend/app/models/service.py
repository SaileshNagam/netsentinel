"""
NetSentinel Device Exposed Service Model
"""
from datetime import datetime
from sqlalchemy import Column, Integer, String, Boolean, DateTime, ForeignKey, Text
from sqlalchemy.orm import relationship
from app.core.database import Base

class DeviceService(Base):
    __tablename__ = "device_services"

    id = Column(Integer, primary_key=True, autoincrement=True)
    device_id = Column(String(64), ForeignKey("devices.id", ondelete="CASCADE"), nullable=False, index=True)
    port = Column(Integer, nullable=False)
    protocol = Column(String(16), default="TCP") # TCP, UDP
    service_name = Column(String(64), nullable=False) # SSH, HTTP, HTTPS, SMB, RDP, DNS
    banner = Column(Text, nullable=True) # Non-intrusive safe banner string
    is_unexpected = Column(Boolean, default=False)
    first_observed = Column(DateTime, default=datetime.utcnow, nullable=False)
    last_observed = Column(DateTime, default=datetime.utcnow, nullable=False)

    device = relationship("Device", back_populates="services")
