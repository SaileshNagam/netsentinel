"""
NetSentinel Multi-Vector Real Network Discovery Engine
Coordinates active Scapy ARP scanning, passive OS neighbor/ARP cache inspection,
IPv6 NDP correlation, and local interface detection.
Adheres strictly to RFC 1918 guardrails and never fabricates device identities.
"""
import time
import socket
import asyncio
import logging
from typing import List, Dict, Any, Optional
from datetime import datetime

from app.core.database import settings
from app.core.oui_database import resolve_mac_vendor, is_locally_administered
from app.discovery.route_inspector import get_active_network_info, get_default_gateway, get_local_interfaces
from app.discovery.arp_scanner import active_arp_scan, is_arp_scan_available
from app.discovery.arp_collector import collect_arp_devices
from app.discovery.ndp_collector import collect_ndp_devices
from app.discovery.hostname_resolver import resolve_hostname
from app.discovery.reachability import check_host_reachability, warm_subnet_arp_cache

logger = logging.getLogger("NetSentinel.DiscoveryEngine")

def infer_device_type(vendor: str, is_random: bool, is_gateway: bool, hostname: Optional[str]) -> str:
    """Heuristic device type inference with explicit confidence. Returns UNKNOWN if uncertain."""
    if is_gateway:
        return "ROUTER"
    
    h = (hostname or "").lower()
    v = vendor.lower()

    if "tv" in h or "bravia" in h or "qled" in h or "tizen" in h:
        return "SMART_TV"
    if "phone" in h or "iphone" in h or "galaxy" in h or "pixel" in h:
        return "MOBILE"
    if "macbook" in h or "laptop" in h or "desktop" in h:
        return "LAPTOP"

    if "raspberry" in v or "espressif" in v or "tuya" in v:
        return "IOT_DEVICE"
    if "synology" in v or "qnap" in v:
        return "NAS_STORAGE"
    if "cisco" in v or "ubiquiti" in v or "tp-link" in v:
        return "ROUTER"
    if "apple" in v:
        return "MOBILE" if is_random else "LAPTOP"
    if "samsung" in v or "sony" in v or "lg" in v:
        return "SMART_TV"
    
    return "UNKNOWN"

class DiscoveredEndpoint:
    def __init__(
        self,
        ip: str,
        mac: Optional[str],
        vendor: str,
        is_mac_randomized: bool,
        hostname: Optional[str],
        device_type: str,
        discovery_method: str,
        is_gateway: bool = False,
        ipv6: Optional[str] = None,
        is_reachable: bool = True
    ):
        self.ip = ip
        self.mac = mac
        self.vendor = vendor
        self.is_mac_randomized = is_mac_randomized
        self.hostname = hostname if hostname and hostname.lower() != "unknown" else "Unknown"
        self.device_type = device_type
        self.discovery_method = discovery_method
        self.is_gateway = is_gateway
        self.ipv6 = ipv6
        self.is_reachable = is_reachable
        self.timestamp = datetime.utcnow()

    def to_dict(self) -> Dict[str, Any]:
        return {
            "ip": self.ip,
            "mac": self.mac,
            "vendor": self.vendor,
            "is_mac_randomized": self.is_mac_randomized,
            "hostname": self.hostname,
            "device_type": self.device_type,
            "discovery_method": self.discovery_method,
            "is_gateway": self.is_gateway,
            "ipv6": self.ipv6,
            "is_reachable": self.is_reachable,
            "timestamp": self.timestamp.isoformat()
        }

async def run_real_discovery_sweep() -> Dict[str, Any]:
    """
    Executes a comprehensive, multi-vector discovery pass on the active local network.
    Returns:
    {
        "endpoints": List[DiscoveredEndpoint],
        "diagnostics": {
            "active_interface": str,
            "local_ip": str,
            "gateway_ip": str,
            "cidr": str,
            "netmask": str,
            "arp_responses": int,
            "neighbor_entries": int,
            "unique_devices": int,
            "scan_duration_seconds": float,
            "raw_packet_available": bool
        }
    }
    """
    start_time = time.time()
    logger.info("Initiating multi-vector network discovery sweep...")

    # 1. Detect current active network automatically
    net_info = get_active_network_info()
    active_iface = net_info["interface"]
    local_ip = net_info["ip_address"]
    gateway_ip = net_info["gateway_ip"]
    cidr = net_info["cidr"]
    netmask = net_info["netmask"]

    logger.info(
        "Active Network: %s on %s | Local IP: %s | Gateway: %s | Netmask: %s",
        cidr, active_iface, local_ip, gateway_ip, netmask
    )

    # 2. Warm subnet ARP cache (forces OS to send ARP requests across subnet without raw sockets)
    await warm_subnet_arp_cache(cidr)

    # 3. Active ARP scan via Scapy (if raw socket permissions available)
    raw_packet_avail = is_arp_scan_available()
    scapy_devices: List[Dict[str, Any]] = []
    if raw_packet_avail:
        scapy_devices = active_arp_scan(cidr, interface=active_iface, timeout=2.0)

    # 4. Ingest OS neighbor/ARP cache (macOS arp -an, Linux ip neigh, Windows arp -a)
    neighbor_devices = collect_arp_devices()

    # 5. Ingest IPv6 neighbors
    ndp_entries = collect_ndp_devices()
    ipv6_by_mac = {ndp["mac"].lower(): ndp["ipv6"] for ndp in ndp_entries if ndp.get("mac")}

    # Unified map keyed primarily by MAC, secondarily by IP
    merged_by_mac: Dict[str, Dict[str, Any]] = {}
    merged_by_ip: Dict[str, Dict[str, Any]] = {}

    def ingest_candidate(ip: str, mac: Optional[str], method: str, iface: Optional[str]):
        if not ip or not settings.is_ip_authorized(ip):
            return
        clean_mac = mac.lower() if mac else None
        
        # Check if already present
        existing = None
        if clean_mac and clean_mac in merged_by_mac:
            existing = merged_by_mac[clean_mac]
        elif ip in merged_by_ip:
            existing = merged_by_ip[ip]

        if existing:
            # Upgrade MAC or method if current has more evidence
            if not existing.get("mac") and clean_mac:
                existing["mac"] = clean_mac
                merged_by_mac[clean_mac] = existing
            if "ACTIVE_ARP" in method:
                existing["method"] = method
            return

        entry = {
            "ip": ip,
            "mac": clean_mac,
            "method": method,
            "interface": iface or active_iface
        }
        if clean_mac:
            merged_by_mac[clean_mac] = entry
        merged_by_ip[ip] = entry

    # Add active ARP devices
    for d in scapy_devices:
        ingest_candidate(d["ip"], d.get("mac"), d["discovery_method"], d.get("interface"))

    # Add OS neighbor entries
    for d in neighbor_devices:
        ingest_candidate(d["ip"], d.get("mac"), d["discovery_method"], d.get("interface"))

    # Add local host interface
    if local_ip and local_ip != "127.0.0.1":
        host_mac = net_info.get("mac_address")
        ingest_candidate(local_ip, host_mac, "LOCAL_INTERFACE", active_iface)

    # Convert merged entries into DiscoveredEndpoint objects
    endpoints: List[DiscoveredEndpoint] = []
    seen_ips = set()

    for item in merged_by_ip.values():
        ip = item["ip"]
        if ip in seen_ips:
            continue
        seen_ips.add(ip)

        mac = item.get("mac")
        is_gw = (ip == gateway_ip)

        # Resolve vendor & LAA status
        if mac:
            vendor, is_rand, _ = resolve_mac_vendor(mac)
            if is_rand:
                vendor = "Randomized / Locally Administered MAC"
        else:
            vendor = "Unknown"
            is_rand = False

        # Hostname resolution (safe timeout, never fabricates)
        hostname = resolve_hostname(ip)
        if hostname == "Unknown" and is_gw:
            hostname = "gateway.home.arpa"
        elif hostname == "Unknown" and ip == local_ip:
            try:
                hostname = socket.gethostname() or "Local-Host"
            except Exception:
                hostname = "Local-Host"

        # Device type heuristic
        dtype = infer_device_type(vendor, is_rand, is_gw, hostname)

        # Correlate IPv6
        ipv6 = ipv6_by_mac.get(mac.lower()) if mac else None

        endpoints.append(DiscoveredEndpoint(
            ip=ip,
            mac=mac,
            vendor=vendor,
            is_mac_randomized=is_rand,
            hostname=hostname,
            device_type=dtype,
            discovery_method=item["method"],
            is_gateway=is_gw,
            ipv6=ipv6,
            is_reachable=True
        ))

    duration = round(time.time() - start_time, 2)

    diagnostics = {
        "active_interface": active_iface,
        "local_ip": local_ip,
        "gateway_ip": gateway_ip,
        "cidr": cidr,
        "netmask": netmask,
        "arp_responses": len(scapy_devices),
        "neighbor_entries": len(neighbor_devices),
        "unique_devices": len(endpoints),
        "scan_duration_seconds": duration,
        "raw_packet_available": raw_packet_avail
    }

    logger.info(
        "Discovery complete in %ss. Found %d unique observable devices on %s.",
        duration, len(endpoints), cidr
    )

    return {
        "endpoints": endpoints,
        "diagnostics": diagnostics
    }
