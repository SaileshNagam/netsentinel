"""
NetSentinel Incidents & Policy Action Endpoints
"""
import hashlib
from datetime import datetime
from typing import List
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.core.database import get_db
from app.models.incident import Incident, ActionStatus
from app.models.audit import AuditEvent
from app.schemas.common import IncidentRead, ActionApprovalRequest
from app.core.websocket_hub import ws_hub

router = APIRouter(prefix="/api/incidents", tags=["Incidents"])

@router.get("", response_model=List[IncidentRead])
async def list_incidents(db: AsyncSession = Depends(get_db)):
    """Retrieve all recorded security incidents and recommended guardian actions."""
    result = await db.execute(select(Incident).order_by(Incident.created_at.desc()))
    return result.scalars().all()

@router.get("/{incident_id}", response_model=IncidentRead)
async def get_incident(incident_id: str, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Incident).where(Incident.id == incident_id))
    incident = result.scalars().first()
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")
    return incident

@router.post("/{incident_id}/action", response_model=IncidentRead)
async def approve_incident_action(
    incident_id: str,
    payload: ActionApprovalRequest,
    db: AsyncSession = Depends(get_db)
):
    """
    Human Guardian Decision Approval / Rejection:
    NetSentinel strictly enforces human-in-the-loop authorization.
    Actions such as BLOCK_DEVICE or ISOLATE are never executed automatically.
    """
    valid_statuses = [ActionStatus.APPROVED.value, ActionStatus.DENIED.value]
    if payload.action_status.upper() not in valid_statuses:
        raise HTTPException(status_code=400, detail=f"Action must be one of: {valid_statuses}")

    result = await db.execute(select(Incident).where(Incident.id == incident_id))
    incident = result.scalars().first()
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")

    incident.action_status = payload.action_status.upper()
    incident.updated_at = datetime.utcnow()

    # Log tamper-evident audit trail
    audit = AuditEvent(
        action="GUARDIAN_ACTION_DECISION",
        actor="SOC_OPERATOR",
        target_resource=f"incident:{incident.id}",
        details=f"Human operator set action '{incident.recommended_action}' to '{incident.action_status}'. Notes: {payload.operator_notes or 'None'}",
        timestamp=datetime.utcnow(),
        event_hash=hashlib.sha256(f"{incident.id}-{incident.action_status}-{datetime.utcnow()}".encode()).hexdigest()
    )
    db.add(audit)
    await db.commit()
    await db.refresh(incident)

    await ws_hub.broadcast("INCIDENT_UPDATED", {
        "incident_id": incident.id,
        "action_status": incident.action_status
    })

    return incident
