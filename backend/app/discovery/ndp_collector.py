"""
NetSentinel IPv6 Neighbor Discovery (NDP) Collector
Parses OS IPv6 neighbor tables (RFC 4861) to track dual-stack IPv6 endpoints.
"""
import subprocess
import re
from typing import List, Dict, Any
from app.core.oui_database import normalize_mac

def parse_macos_ndp(output: str) -> List[Dict[str, Any]]:
    """
    Parses macOS `ndp -an` output:
    Neighbor Linklayer Address Netif Expire St Flgs Prbs
    fe80::cff:a7a8:3c8b:f640%en0 90:cd:e8:d4:13:be en0 23h59m30s S
    """
    neighbors = []
    lines = output.splitlines()
    for line in lines[1:]: # Skip header
        parts = line.split()
        if len(parts) >= 3:
            raw_ip, raw_mac, iface = parts[:3]
            if "(incomplete)" in raw_mac or raw_mac == "(none)":
                continue
            # Strip interface scope if present (e.g. fe80::...%en0)
            ipv6 = raw_ip.split("%")[0]
            if ipv6 == "fe80::1":
                continue

            normalized_mac = normalize_mac(raw_mac)
            if normalized_mac:
                neighbors.append({
                    "ipv6": ipv6,
                    "mac": normalized_mac,
                    "interface": iface,
                    "discovery_method": "NDP_NEIGHBOR_CACHE"
                })
    return neighbors

def collect_ndp_devices() -> List[Dict[str, Any]]:
    """
    Collects IPv6 neighbor discovery entries.
    """
    try:
        output = subprocess.check_output(
            ["/usr/sbin/ndp", "-an"],
            stderr=subprocess.DEVNULL,
            timeout=2
        ).decode()
        return parse_macos_ndp(output)
    except Exception:
        return []
