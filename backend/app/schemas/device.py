"""
Pydantic Schemas for Device Inventory & Classification
"""
from datetime import datetime
from typing import Optional, List
from pydantic import BaseModel, ConfigDict

class ServiceSchema(BaseModel):
    id: int
    port: int
    protocol: str
    service_name: str
    banner: Optional[str] = None
    is_unexpected: bool = False
    first_observed: datetime
    last_observed: datetime

    model_config = ConfigDict(from_attributes=True)

class AddressSchema(BaseModel):
    id: int
    address_type: str
    address_value: str
    first_seen: datetime
    last_seen: datetime

    model_config = ConfigDict(from_attributes=True)

class IdentitySchema(BaseModel):
    id: int
    identity_type: str
    identity_value: str
    confidence: str
    first_seen: datetime
    last_seen: datetime

    model_config = ConfigDict(from_attributes=True)

class TimelineEvent(BaseModel):
    timestamp: datetime
    event_type: str # CONNECTION, ADDRESS_CHANGE, SERVICE_FOUND, RISK_UPDATE, ALERT, USER_ACTION
    title: str
    description: str
    severity: Optional[str] = "INFO"

class DeviceBase(BaseModel):
    user_label: Optional[str] = None
    current_ip: str
    current_mac: Optional[str] = None
    mac_vendor: Optional[str] = "Unknown"
    is_mac_randomized: bool = False
    hostname: Optional[str] = None
    device_type: str = "UNKNOWN"
    os_hint: str = "Unknown"
    trust_status: str = "UNKNOWN"
    is_online: bool = True
    risk_score: int = 0
    risk_severity: str = "LOW"
    confidence_level: str = "UNKNOWN"
    in_baseline: bool = False
    notes: Optional[str] = None

class DeviceCreate(DeviceBase):
    id: str

class DeviceUpdate(BaseModel):
    user_label: Optional[str] = None
    trust_status: Optional[str] = None
    notes: Optional[str] = None

class DeviceClassifyRequest(BaseModel):
    trust_status: str # TRUSTED, UNKNOWN, GUEST, SUSPICIOUS, BLOCKLISTED
    notes: Optional[str] = None

class DeviceRead(DeviceBase):
    id: str
    first_seen: datetime
    last_seen: datetime
    services: List[ServiceSchema] = []
    addresses: List[AddressSchema] = []
    identities: List[IdentitySchema] = []

    model_config = ConfigDict(from_attributes=True)
