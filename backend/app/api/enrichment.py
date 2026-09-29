"""
NetSentinel Device Identity Enrichment REST Endpoints
Exposes Agent 2 (Identity Agent) trigger endpoints.
"""
import logging
from typing import Optional, List
from fastapi import APIRouter, Depends, Query, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.agents.identity_agent import identity_agent

logger = logging.getLogger("NetSentinel.EnrichmentAPI")

router = APIRouter(prefix="/api/enrichment", tags=["Enrichment"])


@router.post("/run")
async def trigger_enrichment(
    device_ids: Optional[List[str]] = Query(None, description="Specific device IDs to enrich (enriches all online if omitted)"),
    skip_port_scan: bool = Query(False, description="Skip TCP port scanning (faster, less data)"),
    db: AsyncSession = Depends(get_db)
):
    """
    Manually triggers the Identity Agent enrichment pipeline.

    For each online device this will:
    - Run a safe TCP connect port scan (unless skip_port_scan=True)
    - Apply multi-vector OS/device-type fingerprinting
    - Record new hostname, vendor, and OS identities
    - Detect and flag unexpected exposed services

    Returns a per-device enrichment summary.
    """
    result = await identity_agent.enrich_all_devices(
        session=db,
        device_ids=device_ids or None,
        skip_port_scan=skip_port_scan
    )
    return {
        "status": "SUCCESS",
        "message": f"Identity enrichment completed for {result['enriched']} devices.",
        "details": result
    }


@router.get("/status")
async def get_enrichment_status():
    """Returns Identity Agent operating status and cumulative enrichment metrics."""
    return {
        "agent": identity_agent.agent_name,
        "status": "OPERATIONAL",
        "total_enrichments_performed": identity_agent.total_enrichments,
        "capabilities": [
            "OUI_VENDOR_LOOKUP",
            "LAA_MAC_RANDOMIZATION_DETECTION",
            "TCP_CONNECT_PORT_SCAN",
            "SERVICE_BANNER_GRABBING",
            "HOSTNAME_MUTATION_TRACKING",
            "OS_FINGERPRINTING",
            "UNEXPECTED_SERVICE_DETECTION"
        ]
    }
