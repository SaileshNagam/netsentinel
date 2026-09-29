"""
NetSentinel Demo API
Endpoints to trigger simulated threat scenarios safely for academic demonstration.
"""
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.demo.event_generator import generate_c2_beacon_demo, generate_port_scan_demo, generate_brute_force_demo

router = APIRouter(prefix="/api/demo", tags=["Demo"])

@router.post("/trigger")
async def trigger_demo_scenario(scenario: str, db: AsyncSession = Depends(get_db)):
    """
    Triggers a safe simulated threat scenario to exercise the detection engine.
    Valid scenarios: 'c2', 'port_scan', 'brute_force'.
    """
    scenario = scenario.lower()
    if scenario == "c2":
        return await generate_c2_beacon_demo(db)
    elif scenario == "port_scan":
        return await generate_port_scan_demo(db)
    elif scenario == "brute_force":
        return await generate_brute_force_demo(db)
    else:
        raise HTTPException(status_code=400, detail="Invalid scenario. Choose 'c2', 'port_scan', or 'brute_force'.")
