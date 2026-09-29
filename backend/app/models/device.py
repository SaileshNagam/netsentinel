"""
NetSentinel Device & Asset Inventory ORM Models
"""
import enum
from datetime import datetime
from sqlalchemy import Column, String, Integer, Boolean, DateTime, Text, ForeignKey, Float
from sqlalchemy.orm import relationship
from app.core.database import Base

class TrustStatus(str, enum.Enum):
    TRUSTED = "TRUSTED"
    UNKNOWN = "UNKNOWN"
    GUEST = "GUEST"
    SUSPICIOUS = "SUSPICIOUS"
    BLOCKLISTED = "BLOCKLISTED"

class DeviceType(str, enum.Enum):
    WORKSTATION = "WORKSTATION"
    LAPTOP = "LAPTOP"
    MOBILE = "MOBILE"
    SMART_TV = "SMART_TV"
    ROUTER = "ROUTER"
    IOT_DEVICE = "IOT_DEVICE"
    NAS_STORAGE = "NAS_STORAGE"
    PRINTER = "PRINTER"
    UNKNOWN = "UNKNOWN"

class RiskSeverity(str, enum.Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

class ConfidenceLevel(str, enum.Enum):
    CONFIRMED = "CONFIRMED"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    UNKNOWN = "UNKNOWN"

class Device(Base):
    __tablename__ = "devices"

    id = Column(String(64), primary_key=True, index=True) # e.g. D-001 or UUID
    user_label = Column(String(128), nullable=True)
    current_ip = Column(String(64), nullable=False, index=True)
    current_mac = Column(String(32), nullable=True, index=True)
    mac_vendor = Column(String(128), default="Unknown")
    is_mac_randomized = Column(Boolean, default=False)
    hostname = Column(String(256), nullable=True)
    device_type = Column(String(64), default=DeviceType.UNKNOWN.value)
    os_hint = Column(String(128), default="Unknown")
    trust_status = Column(String(32), default=TrustStatus.UNKNOWN.value, index=True)
    is_online = Column(Boolean, default=True)
    first_seen = Column(DateTime, default=datetime.utcnow, nullable=False)
    last_seen = Column(DateTime, default=datetime.utcnow, nullable=False)
    risk_score = Column(Integer, default=0) # 0 to 100
    risk_severity = Column(String(32), default=RiskSeverity.LOW.value)
    confidence_level = Column(String(32), default=ConfidenceLevel.UNKNOWN.value)
    in_baseline = Column(Boolean, default=False)
    notes = Column(Text, nullable=True)

    # Relationships
    addresses = relationship("DeviceAddress", back_populates="device", cascade="all, delete-orphan")
    identities = relationship("DeviceIdentity", back_populates="device", cascade="all, delete-orphan")
    services = relationship("DeviceService", back_populates="device", cascade="all, delete-orphan")
    baseline = relationship("BehaviorBaseline", back_populates="device", uselist=False, cascade="all, delete-orphan")
    alerts = relationship("Alert", back_populates="device")
    risk_history = relationship("RiskScoreLog", back_populates="device", cascade="all, delete-orphan")
    incidents = relationship("Incident", back_populates="device")
