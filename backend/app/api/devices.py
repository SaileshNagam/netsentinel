"""
NetSentinel Device Inventory REST Endpoints
"""
import hashlib
from datetime import datetime
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, update
from sqlalchemy.orm import selectinload

from app.core.database import get_db
from app.models.device import Device, TrustStatus, RiskSeverity
from app.models.address import DeviceAddress
from app.models.identity import DeviceIdentity
from app.models.service import DeviceService
from app.models.risk import RiskScoreLog
from app.models.audit import AuditEvent
from app.schemas.device import DeviceRead, DeviceUpdate, DeviceClassifyRequest, TimelineEvent
from app.core.websocket_hub import ws_hub

router = APIRouter(prefix="/api/devices", tags=["Devices"])

@router.get("", response_model=List[DeviceRead])
async def list_devices(
    status: Optional[str] = Query(None, description="Filter by trust status"),
    online_only: bool = Query(False, description="Filter only currently online devices"),
    search: Optional[str] = Query(None, description="Search term for IP, MAC, hostname, vendor"),
    db: AsyncSession = Depends(get_db)
):
    """Retrieve all monitored devices with eager-loaded services, addresses, and identities."""
    query = select(Device).options(
        selectinload(Device.services),
        selectinload(Device.addresses),
        selectinload(Device.identities)
    ).order_by(Device.risk_score.desc(), Device.last_seen.desc())

    if status:
        query = query.where(Device.trust_status == status.upper())
    if online_only:
        query = query.where(Device.is_online == True)
    if search:
        term = f"%{search}%"
        query = query.where(
            (Device.current_ip.ilike(term)) |
            (Device.current_mac.ilike(term)) |
            (Device.hostname.ilike(term)) |
            (Device.mac_vendor.ilike(term)) |
            (Device.user_label.ilike(term)) |
            (Device.id.ilike(term))
        )

    result = await db.execute(query)
    devices = result.scalars().all()
    return devices

@router.get("/online", response_model=List[DeviceRead])
async def list_online_devices(db: AsyncSession = Depends(get_db)):
    """Retrieve all devices currently marked online."""
    query = select(Device).options(
        selectinload(Device.services),
        selectinload(Device.addresses),
        selectinload(Device.identities)
    ).where(Device.is_online == True).order_by(Device.risk_score.desc(), Device.last_seen.desc())
    
    result = await db.execute(query)
    return result.scalars().all()

@router.get("/{device_id}", response_model=DeviceRead)
async def get_device(device_id: str, db: AsyncSession = Depends(get_db)):
    """Retrieve single device dossier."""
    query = select(Device).options(
        selectinload(Device.services),
        selectinload(Device.addresses),
        selectinload(Device.identities)
    ).where(Device.id == device_id)
    
    result = await db.execute(query)
    device = result.scalars().first()
    if not device:
        raise HTTPException(status_code=404, detail=f"Device '{device_id}' not found")
    return device

@router.post("/{device_id}/classify", response_model=DeviceRead)
async def classify_device(
    device_id: str,
    payload: DeviceClassifyRequest,
    db: AsyncSession = Depends(get_db)
):
    """
    Classify a device as TRUSTED, UNKNOWN, GUEST, SUSPICIOUS, or BLOCKLISTED.
    Recalculates risk score based on human classification decision.
    """
    valid_statuses = [s.value for s in TrustStatus]
    if payload.trust_status.upper() not in valid_statuses:
        raise HTTPException(status_code=400, detail=f"Invalid status. Must be one of: {valid_statuses}")

    query = select(Device).options(
        selectinload(Device.services),
        selectinload(Device.addresses),
        selectinload(Device.identities)
    ).where(Device.id == device_id)
    
    result = await db.execute(query)
    device = result.scalars().first()
    if not device:
        raise HTTPException(status_code=404, detail=f"Device '{device_id}' not found")

    old_status = device.trust_status
    device.trust_status = payload.trust_status.upper()
    if payload.notes:
        device.notes = payload.notes

    # Dynamic risk adjustment based on trust classification
    if device.trust_status == TrustStatus.TRUSTED.value:
        device.risk_score = max(0, device.risk_score - 30)
    elif device.trust_status == TrustStatus.BLOCKLISTED.value:
        device.risk_score = 100
    elif device.trust_status == TrustStatus.SUSPICIOUS.value:
        device.risk_score = max(device.risk_score, 65)

    # Recalculate severity band
    if device.risk_score >= 85:
        device.risk_severity = RiskSeverity.CRITICAL.value
    elif device.risk_score >= 60:
        device.risk_severity = RiskSeverity.HIGH.value
    elif device.risk_score >= 30:
        device.risk_severity = RiskSeverity.MEDIUM.value
    else:
        device.risk_severity = RiskSeverity.LOW.value

    # Record Audit Event
    audit = AuditEvent(
        action="CLASSIFY_DEVICE",
        actor="OPERATOR",
        target_resource=f"device:{device_id}",
        details=f"Changed trust status from {old_status} to {device.trust_status}. New risk score: {device.risk_score}.",
        timestamp=datetime.utcnow(),
        event_hash=hashlib.sha256(f"{device_id}-{device.trust_status}-{datetime.utcnow()}".encode()).hexdigest()
    )
    db.add(audit)
    await db.commit()
    await db.refresh(device)

    # Broadcast event via WebSocket
    await ws_hub.broadcast("DEVICE_UPDATED", {
        "device_id": device.id,
        "trust_status": device.trust_status,
        "risk_score": device.risk_score,
        "risk_severity": device.risk_severity
    })

    return device

@router.get("/{device_id}/history")
async def get_device_history(device_id: str, db: AsyncSession = Depends(get_db)):
    """
    Returns the complete persistent inventory ledger for a device.
    Includes full address history (IP/MAC/IPv6 observations) and
    all recorded identities (hostname mutations, OS hints, OUI records).
    This is the authoritative source for 'who has this device been?'
    """
    query = select(Device).options(
        selectinload(Device.addresses),
        selectinload(Device.identities),
        selectinload(Device.services)
    ).where(Device.id == device_id)

    result = await db.execute(query)
    device = result.scalars().first()
    if not device:
        raise HTTPException(status_code=404, detail=f"Device '{device_id}' not found")

    # Build a sorted address ledger
    address_ledger = sorted(
        [
            {
                "id": addr.id,
                "type": addr.address_type,
                "value": addr.address_value,
                "first_seen": addr.first_seen.isoformat(),
                "last_seen": addr.last_seen.isoformat(),
            }
            for addr in device.addresses
        ],
        key=lambda x: x["first_seen"],
        reverse=True
    )

    # Build a sorted identity ledger
    identity_ledger = sorted(
        [
            {
                "id": ident.id,
                "type": ident.identity_type,
                "value": ident.identity_value,
                "confidence": ident.confidence,
                "first_seen": ident.first_seen.isoformat(),
                "last_seen": ident.last_seen.isoformat(),
            }
            for ident in device.identities
        ],
        key=lambda x: x["first_seen"],
        reverse=True
    )

    # Build services ledger
    services_ledger = sorted(
        [
            {
                "id": svc.id,
                "port": svc.port,
                "protocol": svc.protocol,
                "service_name": svc.service_name,
                "banner": svc.banner,
                "is_unexpected": svc.is_unexpected,
                "first_observed": svc.first_observed.isoformat(),
                "last_observed": svc.last_observed.isoformat(),
            }
            for svc in device.services
        ],
        key=lambda x: x["first_observed"],
        reverse=True
    )

    return {
        "device_id": device.id,
        "current_state": {
            "ip": device.current_ip,
            "mac": device.current_mac,
            "hostname": device.hostname,
            "trust_status": device.trust_status,
            "risk_score": device.risk_score,
            "risk_severity": device.risk_severity,
            "device_type": device.device_type,
            "os_hint": device.os_hint,
            "confidence_level": device.confidence_level,
            "is_online": device.is_online,
            "first_seen": device.first_seen.isoformat(),
            "last_seen": device.last_seen.isoformat(),
        },
        "address_history": address_ledger,
        "identity_history": identity_ledger,
        "exposed_services": services_ledger,
        "summary": {
            "unique_ips_observed": len({a["value"] for a in address_ledger if a["type"] == "IPV4"}),
            "unique_macs_observed": len({a["value"] for a in address_ledger if a["type"] == "MAC"}),
            "identity_records": len(identity_ledger),
            "exposed_service_count": len(services_ledger),
            "unexpected_services": sum(1 for s in services_ledger if s["is_unexpected"]),
        }
    }


@router.get("/{device_id}/timeline", response_model=List[TimelineEvent])
async def get_device_timeline(device_id: str, db: AsyncSession = Depends(get_db)):
    """
    Constructs a unified chronological timeline for a specific device.
    Aggregates first appearance, address observations, service discoveries, risk updates, and user actions.
    """
    query = select(Device).options(
        selectinload(Device.services),
        selectinload(Device.addresses),
        selectinload(Device.identities),
        selectinload(Device.alerts),
        selectinload(Device.risk_history)
    ).where(Device.id == device_id)
    
    result = await db.execute(query)
    device = result.scalars().first()
    if not device:
        raise HTTPException(status_code=404, detail="Device not found")

    events: List[TimelineEvent] = []

    # 1. First Seen
    events.append(TimelineEvent(
        timestamp=device.first_seen,
        event_type="CONNECTION",
        title="Device Discovered on Network",
        description=f"Device first observed via ARP probe at IP {device.current_ip} with MAC {device.current_mac or 'Unknown'}.",
        severity="INFO"
    ))

    # 2. Hostname/Identity observations
    for identity in device.identities:
        events.append(TimelineEvent(
            timestamp=identity.first_seen,
            event_type="IDENTITY",
            title=f"Identity Observed ({identity.identity_type})",
            description=f"Identified '{identity.identity_value}' with {identity.confidence} confidence.",
            severity="INFO"
        ))

    # 3. Services discovered
    for svc in device.services:
        events.append(TimelineEvent(
            timestamp=svc.first_observed,
            event_type="SERVICE_FOUND",
            title=f"Exposed Service Detected: {svc.port}/{svc.protocol} ({svc.service_name})",
            description=f"Safe connect probe observed open port {svc.port}. Banner: {svc.banner or 'None'}. Unexpected: {svc.is_unexpected}.",
            severity="WARNING" if svc.is_unexpected else "INFO"
        ))

    # 4. Alerts
    for alt in device.alerts:
        events.append(TimelineEvent(
            timestamp=alt.created_at,
            event_type="ALERT",
            title=f"Security Alert: {alt.title}",
            description=alt.description,
            severity=alt.severity
        ))

    # 5. Risk score transitions
    for r in device.risk_history:
        events.append(TimelineEvent(
            timestamp=r.calculated_at,
            event_type="RISK_UPDATE",
            title=f"Risk Score Assessed: {r.score} / 100 ({r.severity})",
            description=f"Calculated based on {len(r.factors_json)} evaluated factors.",
            severity=r.severity
        ))

    # Sort descending by timestamp
    events.sort(key=lambda x: x.timestamp, reverse=True)
    return events
