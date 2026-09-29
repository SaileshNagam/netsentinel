"""
NetSentinel Security Posture Summary Endpoint
"""
from datetime import datetime, timedelta
from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func

from app.core.database import get_db
from app.models.device import Device, TrustStatus, RiskSeverity
from app.models.service import DeviceService
from app.models.alert import Alert, AlertStatus
from app.schemas.common import SecurityPostureStats

router = APIRouter(prefix="/api/posture", tags=["Posture"])

@router.get("", response_model=SecurityPostureStats)
async def get_security_posture(db: AsyncSession = Depends(get_db)):
    """Computes real-time executive security posture metrics."""
    # 1. Device counts by trust status
    all_devices = (await db.execute(select(Device))).scalars().all()
    
    total_connected = sum(1 for d in all_devices if d.is_online)
    trusted = sum(1 for d in all_devices if d.trust_status == TrustStatus.TRUSTED.value)
    unknown = sum(1 for d in all_devices if d.trust_status == TrustStatus.UNKNOWN.value)
    suspicious = sum(1 for d in all_devices if d.trust_status == TrustStatus.SUSPICIOUS.value)
    blocklisted = sum(1 for d in all_devices if d.trust_status == TrustStatus.BLOCKLISTED.value)
    high_risk = sum(1 for d in all_devices if d.risk_score >= 60)
    baseline_count = sum(1 for d in all_devices if d.in_baseline)

    # 2. Devices seen today (last 24 hours)
    cutoff = datetime.utcnow() - timedelta(hours=24)
    seen_today = sum(1 for d in all_devices if d.last_seen >= cutoff)

    # 3. Open services total
    services_count = (await db.execute(select(func.count(DeviceService.id)))).scalar() or 0

    # 4. Active alerts count
    active_alerts = (await db.execute(
        select(func.count(Alert.id)).where(Alert.status == AlertStatus.ACTIVE.value)
    )).scalar() or 0

    # 5. Average / Weighted network risk score
    if all_devices:
        avg_risk = int(sum(d.risk_score for d in all_devices) / len(all_devices))
    else:
        avg_risk = 0

    return SecurityPostureStats(
        total_connected=total_connected,
        trusted_devices=trusted,
        unknown_devices=unknown,
        suspicious_devices=suspicious,
        blocklisted_devices=blocklisted,
        high_risk_devices=high_risk,
        devices_seen_today=seen_today,
        open_services_total=services_count,
        active_alerts_count=active_alerts,
        network_risk_score=avg_risk,
        learn_baseline_active=False,
        baseline_device_count=baseline_count
    )
