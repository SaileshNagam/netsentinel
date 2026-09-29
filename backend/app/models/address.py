"""
NetSentinel Device Address History Model
"""
from datetime import datetime
from sqlalchemy import Column, Integer, String, DateTime, ForeignKey
from sqlalchemy.orm import relationship
from app.core.database import Base

class DeviceAddress(Base):
    __tablename__ = "device_addresses"

    id = Column(Integer, primary_key=True, autoincrement=True)
    device_id = Column(String(64), ForeignKey("devices.id", ondelete="CASCADE"), nullable=False, index=True)
    address_type = Column(String(16), nullable=False) # IPV4, IPV6, MAC
    address_value = Column(String(64), nullable=False, index=True)
    first_seen = Column(DateTime, default=datetime.utcnow, nullable=False)
    last_seen = Column(DateTime, default=datetime.utcnow, nullable=False)

    device = relationship("Device", back_populates="addresses")
