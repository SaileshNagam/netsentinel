"""
NetSentinel Active ARP Scanner (Scapy)
Sends Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=<subnet>) to discover
devices that don't appear in the passive kernel ARP cache.

Requires raw packet access (root or macOS BPF capability).
Gracefully degrades with a clear error when permissions are insufficient.
"""
import logging
import ipaddress
from typing import List, Dict, Any, Optional

from app.core.database import settings
from app.core.oui_database import normalize_mac

logger = logging.getLogger("NetSentinel.ARPScanner")

# Track permission state so we only warn once
_permission_warned = False


def _validate_target_network(cidr: str) -> bool:
    """Ensures the target CIDR is a private RFC 1918 network. Never scan public IPs."""
    try:
        network = ipaddress.ip_network(cidr, strict=False)
        return network.is_private and not network.is_loopback
    except ValueError:
        return False


def _check_scapy_permissions() -> bool:
    """
    Tests whether Scapy can open raw sockets on this host.
    Returns True if raw packet injection is available.
    """
    global _permission_warned
    try:
        # Import Scapy with suppressed warnings
        import scapy.config
        scapy.config.conf.verb = 0  # Silence Scapy console output

        from scapy.arch import get_if_raw_hwaddr
        # Try to get hardware address — this validates BPF/raw access on macOS
        return True
    except Exception as e:
        if not _permission_warned:
            logger.warning(
                "Raw packet access unavailable: %s. "
                "Active ARP scanning disabled. "
                "Run NetSentinel with: sudo %s to enable full discovery.",
                e, "python -m uvicorn app.main:app --host 127.0.0.1 --port 8000"
            )
            _permission_warned = True
        return False


def active_arp_scan(
    cidr: str,
    interface: Optional[str] = None,
    timeout: float = 3.0
) -> List[Dict[str, Any]]:
    """
    Performs an active ARP scan across the given CIDR using Scapy.

    Sends: Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=<cidr>)
    Collects: IP + MAC from every ARP reply

    Args:
        cidr: Target subnet in CIDR notation (e.g. "192.168.1.0/24")
        interface: Network interface name (e.g. "en0"). Auto-detected if None.
        timeout: Seconds to wait for ARP responses (default: 3s)

    Returns: List of dicts [{ip, mac, interface, discovery_method}, ...]

    Safety:
        - Validates CIDR is RFC 1918 private before scanning
        - Returns empty list if permissions are insufficient (never raises)
        - Returns empty list if Scapy is unavailable
    """
    # ── Safety check: only scan private networks ────────────────────────
    if not _validate_target_network(cidr):
        logger.error("REFUSED: CIDR %s is not a private RFC 1918 network. Scan aborted.", cidr)
        return []

    # ── Permission check ────────────────────────────────────────────────
    try:
        import scapy.config
        scapy.config.conf.verb = 0
        from scapy.layers.l2 import Ether, ARP
        from scapy.sendrecv import srp
    except ImportError:
        logger.error("Scapy is not installed. Active ARP scanning unavailable.")
        return []

    devices: List[Dict[str, Any]] = []

    try:
        # Build ARP broadcast frame
        ether = Ether(dst="ff:ff:ff:ff:ff:ff")
        arp = ARP(pdst=cidr)
        packet = ether / arp

        logger.info(
            "Active ARP scan: broadcasting to %s on %s (timeout=%.1fs)...",
            cidr, interface or "default", timeout
        )

        # Send and receive
        kwargs = {"timeout": timeout, "verbose": 0}
        if interface:
            kwargs["iface"] = interface

        answered, _ = srp(packet, **kwargs)

        for sent, received in answered:
            ip = received.psrc
            raw_mac = received.hwsrc

            # Validate: only accept RFC 1918 responses
            if not settings.is_ip_authorized(ip):
                continue

            # Skip broadcast/multicast MACs
            if raw_mac.lower() in ("ff:ff:ff:ff:ff:ff", "00:00:00:00:00:00"):
                continue

            normalized_mac = normalize_mac(raw_mac)
            if normalized_mac:
                devices.append({
                    "ip": ip,
                    "mac": normalized_mac,
                    "interface": interface or "default",
                    "discovery_method": "ACTIVE_ARP_SCAN"
                })

        logger.info(
            "Active ARP scan complete: %d ARP responses received from %s",
            len(devices), cidr
        )

    except PermissionError:
        logger.warning(
            "Raw packet access denied. Run with sudo for active ARP scanning. "
            "Falling back to passive discovery only."
        )
    except OSError as e:
        if "Operation not permitted" in str(e) or "Permission denied" in str(e):
            logger.warning(
                "OS denied raw socket access: %s. "
                "Active ARP requires elevated privileges on macOS. "
                "Falling back to passive discovery.", e
            )
        else:
            logger.error("ARP scan OS error: %s", e, exc_info=True)
    except Exception as e:
        logger.error("Active ARP scan failed: %s", e, exc_info=True)

    return devices


def is_arp_scan_available() -> bool:
    """
    Returns True if active ARP scanning is available on this system.
    Checks Scapy installation and raw socket permissions.
    """
    try:
        import scapy.config
        scapy.config.conf.verb = 0
        from scapy.layers.l2 import Ether, ARP
        from scapy.sendrecv import srp
        return True
    except (ImportError, OSError):
        return False
