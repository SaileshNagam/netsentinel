"""
NetSentinel System Telemetry API
"""
from fastapi import APIRouter
from app.monitoring.common_monitor import collect_system_telemetry

router = APIRouter(prefix="/api/system", tags=["System"])

@router.get("/status")
async def get_system_status():
    """
    Returns real-time host hardware and OS telemetry.
    """
    return collect_system_telemetry()
