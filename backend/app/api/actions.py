"""
NetSentinel Actions API
Endpoints for the dashboard to Approve, Reject, or Simulate pending defensive actions.
"""
from typing import Dict, Any
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.core.database import get_db
from app.models.response import DefensiveAction, ActionStatus
from app.response.response_manager import response_manager
from pydantic import BaseModel

router = APIRouter(prefix="/api/actions", tags=["Actions"])

class ActionDecisionRequest(BaseModel):
    operator: str = "SOC_OPERATOR"
    notes: str = ""

@router.get("")
async def list_actions(db: AsyncSession = Depends(get_db)):
    """Retrieve all defensive actions (history and pending)."""
    result = await db.execute(select(DefensiveAction).order_by(DefensiveAction.created_at.desc()))
    return result.scalars().all()

@router.get("/{action_id}")
async def get_action(action_id: int, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(DefensiveAction).where(DefensiveAction.id == action_id))
    action = result.scalars().first()
    if not action:
        raise HTTPException(status_code=404, detail="Action not found")
    return action

@router.post("/{action_id}/approve")
async def approve_and_execute_action(
    action_id: int, 
    payload: ActionDecisionRequest, 
    db: AsyncSession = Depends(get_db)
):
    """
    Approve a pending action and execute it immediately.
    If global simulation mode is ON, this will still result in a safe dry run.
    """
    result = await db.execute(select(DefensiveAction).where(DefensiveAction.id == action_id))
    action = result.scalars().first()
    if not action:
        raise HTTPException(status_code=404, detail="Action not found")
        
    if action.status != ActionStatus.PENDING_APPROVAL.value:
        raise HTTPException(status_code=400, detail=f"Cannot approve action in status: {action.status}")

    # 1. Update status to APPROVED
    action.status = ActionStatus.APPROVED.value
    action.operator = payload.operator
    if payload.notes:
        action.reason = (action.reason or "") + f" | Operator Note: {payload.notes}"
    await db.commit()
    
    # 2. Execute via Response Manager
    exec_result = await response_manager.execute_action(db, action_id, operator=payload.operator, force_dry_run=False)
    
    return {
        "status": "success",
        "action_id": action_id,
        "execution": exec_result
    }

@router.post("/{action_id}/simulate")
async def simulate_action(
    action_id: int, 
    payload: ActionDecisionRequest, 
    db: AsyncSession = Depends(get_db)
):
    """
    Approve and execute a pending action FORCEFULLY in Dry Run / Simulation mode.
    Does not modify the underlying OS.
    """
    result = await db.execute(select(DefensiveAction).where(DefensiveAction.id == action_id))
    action = result.scalars().first()
    if not action:
        raise HTTPException(status_code=404, detail="Action not found")

    if action.status != ActionStatus.PENDING_APPROVAL.value:
        raise HTTPException(status_code=400, detail=f"Cannot simulate action in status: {action.status}")

    action.status = ActionStatus.APPROVED.value
    action.operator = payload.operator
    await db.commit()
    
    exec_result = await response_manager.execute_action(db, action_id, operator=payload.operator, force_dry_run=True)
    
    return {
        "status": "success",
        "action_id": action_id,
        "execution": exec_result
    }

@router.post("/{action_id}/reject")
async def reject_action(
    action_id: int, 
    payload: ActionDecisionRequest, 
    db: AsyncSession = Depends(get_db)
):
    """
    Reject a pending defensive action. It will be permanently aborted.
    """
    result = await db.execute(select(DefensiveAction).where(DefensiveAction.id == action_id))
    action = result.scalars().first()
    if not action:
        raise HTTPException(status_code=404, detail="Action not found")

    if action.status != ActionStatus.PENDING_APPROVAL.value:
        raise HTTPException(status_code=400, detail=f"Cannot reject action in status: {action.status}")

    action.status = ActionStatus.REJECTED.value
    action.operator = payload.operator
    if payload.notes:
        action.reason = (action.reason or "") + f" | Rejected Note: {payload.notes}"
    
    # Audit log (simple integration)
    from app.models.audit import AuditEvent
    import hashlib
    from datetime import datetime, timezone
    
    evt_hash = hashlib.sha256(f"{action.id}:REJECTED:{payload.operator}".encode()).hexdigest()
    audit = AuditEvent(
        action="ACTION_REJECTED",
        actor=payload.operator,
        target_resource=f"defensive_action:{action.id}",
        details=f"Human operator rejected the action. Note: {payload.notes}",
        timestamp=datetime.now(timezone.utc),
        event_hash=evt_hash
    )
    db.add(audit)
    
    await db.commit()
    
    return {
        "status": "success",
        "action_id": action_id,
        "message": "Action successfully rejected and audited."
    }
