"""
NetSentinel Evidence Locker Model (SHA-256 Tamper-Evident Integrity)
"""
from datetime import datetime
from sqlalchemy import Column, String, Integer, DateTime, ForeignKey, Text
from app.core.database import Base

class EvidencePackage(Base):
    __tablename__ = "evidence_locker"

    id = Column(String(64), primary_key=True, index=True) # UUID
    incident_id = Column(String(64), ForeignKey("incidents.id", ondelete="CASCADE"), nullable=True, index=True)
    device_id = Column(String(64), ForeignKey("devices.id", ondelete="SET NULL"), nullable=True, index=True)
    evidence_type = Column(String(64), nullable=False) # RAW_ARP, SERVICE_BANNER, IDENTITY_MUTATION, FULL_DOSSIER
    data_blob = Column(Text, nullable=False) # JSON formatted raw telemetry and context
    sha256_hash = Column(String(64), nullable=False, index=True) # SHA-256 Digest
    captured_at = Column(DateTime, default=datetime.utcnow, nullable=False, index=True)
