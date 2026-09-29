"""
NetSentinel Process Inventory API
"""
from typing import List, Dict, Any
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.core.database import get_db
from app.models.telemetry import ProcessSnapshot
from app.monitoring.common_monitor import collect_processes

router = APIRouter(prefix="/api/processes", tags=["Processes"])

@router.get("")
async def get_live_processes(simulation: bool = False):
    """
    Returns a real-time snapshot of currently running processes.
    Does not persist to DB.
    """
    return collect_processes(simulation=simulation)

@router.get("/{pid}")
async def get_process_details(pid: int, simulation: bool = False):
    """
    Returns details for a specific PID from the live system.
    """
    procs = collect_processes(simulation=simulation)
    for p in procs:
        if p["pid"] == pid:
            return p
    raise HTTPException(status_code=404, detail="Process not found or no longer running.")

@router.get("/{pid}/connections")
async def get_process_connections(pid: int, simulation: bool = False):
    """
    Returns live network connections owned by a specific PID.
    """
    from app.monitoring.common_monitor import collect_connections
    conns = collect_connections(simulation=simulation)
    return [c for c in conns if c.get("pid") == pid]
