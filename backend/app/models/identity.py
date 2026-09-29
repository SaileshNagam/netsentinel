"""
NetSentinel Device Identity Mutation Model
"""
from datetime import datetime
from sqlalchemy import Column, Integer, String, DateTime, ForeignKey
from sqlalchemy.orm import relationship
from app.core.database import Base

class DeviceIdentity(Base):
    __tablename__ = "device_identities"

    id = Column(Integer, primary_key=True, autoincrement=True)
    device_id = Column(String(64), ForeignKey("devices.id", ondelete="CASCADE"), nullable=False, index=True)
    identity_type = Column(String(32), nullable=False) # HOSTNAME, VENDOR_OUI, MDNS_NAME, USER_AGENT
    identity_value = Column(String(256), nullable=False)
    confidence = Column(String(32), default="MEDIUM")
    first_seen = Column(DateTime, default=datetime.utcnow, nullable=False)
    last_seen = Column(DateTime, default=datetime.utcnow, nullable=False)

    device = relationship("Device", back_populates="identities")
