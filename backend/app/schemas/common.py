"""
Pydantic Schemas for Alerts, Risk, Incidents, and Posture
"""
from datetime import datetime
from typing import Optional, List, Dict, Any
from pydantic import BaseModel, ConfigDict

# Alerts
class AlertBase(BaseModel):
    device_id: Optional[str] = None
    rule_id: str
    title: str
    description: str
    severity: str = "MEDIUM" # LOW, MEDIUM, HIGH, CRITICAL
    status: str = "ACTIVE"
    confidence: str = "HIGH"
    evidence_data: str = "{}"

class AlertRead(AlertBase):
    id: str
    deduplication_hash: str
    created_at: datetime
    acknowledged_at: Optional[datetime] = None
    resolved_at: Optional[datetime] = None

    model_config = ConfigDict(from_attributes=True)

class AlertAcknowledgeRequest(BaseModel):
    status: str = "ACKNOWLEDGED" # ACKNOWLEDGED, RESOLVED, IGNORED

# Risk
class RiskFactor(BaseModel):
    rule_id: str
    factor_name: str
    score_delta: int
    reason: str
    evidence: str

class RiskAssessmentRead(BaseModel):
    device_id: str
    score: int
    severity: str
    confidence: str
    factors: List[RiskFactor]
    evidence_summary: str
    calculated_at: datetime

# Incidents & Human Guardian
class IncidentRead(BaseModel):
    id: str
    device_id: str
    title: str
    severity: str
    status: str
    recommended_action: str
    action_status: str
    summary: str
    evidence_package_hash: str
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)

class ActionApprovalRequest(BaseModel):
    action_status: str # APPROVED, DENIED
    operator_notes: Optional[str] = None

# Security Posture Dashboard Overview
class SecurityPostureStats(BaseModel):
    total_connected: int
    trusted_devices: int
    unknown_devices: int
    suspicious_devices: int
    blocklisted_devices: int
    high_risk_devices: int
    devices_seen_today: int
    open_services_total: int
    active_alerts_count: int
    network_risk_score: int # Average/aggregate local network risk
    learn_baseline_active: bool
    baseline_device_count: int

# Simulation
class ScenarioLaunchRequest(BaseModel):
    scenario_id: str # e.g. "unknown_rogue_device", "mac_spoofing", "midnight_iot", "ip_conflict", "smb_exposure"

class ScenarioStep(BaseModel):
    step_number: int
    agent_name: str # DiscoveryAgent, IdentityAgent, BehaviorAgent, RiskAgent, AlertAgent, Guardian
    action: str
    result: str
    evidence: str
    confidence: str
    timestamp: datetime
