"""
NetSentinel Security Alerts REST Endpoints
"""
from datetime import datetime
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, update

from app.core.database import get_db
from app.models.alert import Alert, AlertStatus
from app.schemas.common import AlertRead, AlertAcknowledgeRequest
from app.core.websocket_hub import ws_hub

router = APIRouter(prefix="/api/alerts", tags=["Alerts"])

@router.get("", response_model=List[AlertRead])
async def list_alerts(
    status: Optional[str] = Query(None, description="Filter by status: ACTIVE, ACKNOWLEDGED, RESOLVED"),
    severity: Optional[str] = Query(None, description="Filter by severity: LOW, MEDIUM, HIGH, CRITICAL"),
    db: AsyncSession = Depends(get_db)
):
    """Retrieve security alerts ordered by timestamp descending."""
    query = select(Alert).order_by(Alert.created_at.desc())
    if status:
        query = query.where(Alert.status == status.upper())
    if severity:
        query = query.where(Alert.severity == severity.upper())

    result = await db.execute(query)
    alerts = result.scalars().all()
    return alerts

@router.post("/{alert_id}/status", response_model=AlertRead)
async def update_alert_status(
    alert_id: str,
    payload: AlertAcknowledgeRequest,
    db: AsyncSession = Depends(get_db)
):
    """Update alert triage status (ACKNOWLEDGED, RESOLVED, IGNORED)."""
    valid_statuses = [s.value for s in AlertStatus]
    if payload.status.upper() not in valid_statuses:
        raise HTTPException(status_code=400, detail=f"Status must be one of: {valid_statuses}")

    result = await db.execute(select(Alert).where(Alert.id == alert_id))
    alert = result.scalars().first()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")

    alert.status = payload.status.upper()
    now = datetime.utcnow()
    if alert.status == AlertStatus.ACKNOWLEDGED.value:
        alert.acknowledged_at = now
    elif alert.status == AlertStatus.RESOLVED.value:
        alert.resolved_at = now

    await db.commit()
    await db.refresh(alert)

    # Broadcast status change
    await ws_hub.broadcast("ALERT_UPDATED", {
        "alert_id": alert.id,
        "status": alert.status
    })

    return alert
