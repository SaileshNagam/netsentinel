"""
NetSentinel Live Connections API
"""
from typing import List, Dict, Any
from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.core.database import get_db
from app.models.telemetry import ConnectionEvent
from app.monitoring.common_monitor import collect_connections

router = APIRouter(prefix="/api/connections", tags=["Connections"])

@router.get("/live")
async def get_live_connections(simulation: bool = False):
    """
    Returns a real-time snapshot of current host network connections.
    Does not persist to DB.
    """
    return collect_connections(simulation=simulation)

@router.get("/history")
async def get_connection_history(limit: int = 1000, db: AsyncSession = Depends(get_db)):
    """
    Retrieve historical connection snapshots from the database.
    """
    result = await db.execute(
        select(ConnectionEvent).order_by(ConnectionEvent.timestamp.desc()).limit(limit)
    )
    return result.scalars().all()
