"""
NetSentinel Security Events API
Provides access to normalized host security logs (Linux auth.log / Windows Security Event Log).
"""
import platform
from typing import List, Dict, Any
from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.core.database import get_db
from app.models.telemetry import SecurityEvent
from app.monitoring.linux_monitor import parse_auth_log
from app.monitoring.windows_monitor import get_windows_event_log_events

router = APIRouter(prefix="/api/security-events", tags=["Logs"])

@router.get("/live")
async def get_live_security_events(limit: int = 100):
    """
    Parses and returns recent OS security events in real-time.
    """
    if platform.system() == "Windows":
        return get_windows_event_log_events(max_events=limit)
    elif platform.system() == "Linux":
        return parse_auth_log(max_lines=limit * 5) # Scan more raw lines to find relevant events
    return []

@router.get("/history")
async def get_historical_security_events(limit: int = 1000, db: AsyncSession = Depends(get_db)):
    """
    Retrieve historical security events from the database.
    """
    result = await db.execute(
        select(SecurityEvent).order_by(SecurityEvent.timestamp.desc()).limit(limit)
    )
    return result.scalars().all()
