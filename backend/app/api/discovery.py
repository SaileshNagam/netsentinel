"""
NetSentinel Network Discovery REST Endpoints
Provides interface detection, active/passive discovery triggers, and operational status.
"""
from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession
from app.core.database import get_db
from app.agents.discovery_agent import discovery_agent
from app.discovery.route_inspector import get_local_interfaces, get_default_gateway, get_active_network_info
from app.discovery.arp_scanner import is_arp_scan_available

router = APIRouter(prefix="", tags=["Discovery"])

@router.get("/api/network/interface")
@router.get("/api/discovery/active-interface")
async def get_active_network():
    """
    Returns the auto-detected primary network interface and calculated subnet CIDR.
    """
    net_info = get_active_network_info()
    return {
        "status": "SUCCESS",
        "active_interface": net_info["interface"],
        "ip_address": net_info["ip_address"],
        "subnet_mask": net_info["netmask"],
        "cidr": net_info["cidr"],
        "default_gateway": net_info["gateway_ip"],
        "network_address": net_info["network_address"],
        "broadcast_address": net_info["broadcast_address"],
        "is_rfc1918_private": net_info["is_rfc1918"],
        "raw_packet_capable": is_arp_scan_available()
    }

@router.post("/api/network/discover")
@router.post("/api/discovery/scan")
async def trigger_discovery_scan(db: AsyncSession = Depends(get_db)):
    """
    Triggers an immediate multi-vector Layer 2/3 network discovery sweep on the active local subnet.
    """
    result = await discovery_agent.execute_discovery_sweep(db)
    return {
        "status": "SUCCESS",
        "message": f"Discovery sweep completed. {result['endpoints_observed']} observable endpoints found.",
        "details": result
    }

@router.get("/api/discovery/status")
async def get_discovery_status():
    """
    Returns Discovery Agent operating status, diagnostic capabilities, and permission details.
    """
    arp_avail = is_arp_scan_available()
    return {
        "agent": discovery_agent.agent_name,
        "status": "OPERATIONAL",
        "last_scan_time": discovery_agent.last_scan_time.isoformat(),
        "total_scans_performed": discovery_agent.total_scans_performed,
        "last_discovered_count": discovery_agent.last_discovered_count,
        "last_diagnostics": discovery_agent.last_diagnostics,
        "permissions": {
            "raw_packet_capture": arp_avail,
            "mode": "ACTIVE_SCAPY_AND_PASSIVE" if arp_avail else "PASSIVE_CACHE_AND_TCP_WARMING",
            "elevation_notice": None if arp_avail else "Run NetSentinel with sudo for raw packet injection."
        },
        "vectors_enabled": [
            "KERNEL_ARP_CACHE",
            "ACTIVE_SCAPY_ARP" if arp_avail else "PASSIVE_ARP_CACHE",
            "SUBNET_ARP_WARMING",
            "NDP_IPV6_CORRELATION",
            "ROUTING_TABLE_INSPECTION",
            "IEEE_OUI_RESOLUTION",
            "MAC_RANDOMIZATION_LAA_CHECK",
            "SAFE_HOSTNAME_RESOLUTION"
        ]
    }

@router.get("/api/discovery/interfaces")
async def get_interfaces():
    """
    Returns all non-loopback network interfaces and the default gateway.
    """
    interfaces = get_local_interfaces()
    gateway = get_default_gateway()
    return {
        "active_interfaces": interfaces,
        "default_gateway": gateway
    }
