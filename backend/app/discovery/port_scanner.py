"""
NetSentinel Safe Port & Service Scanner
Performs low-noise TCP connect probes to detect exposed services on LAN hosts.
Uses asyncio with per-host timeouts. Never sends raw packets.
No root privileges required.
"""
import asyncio
import logging
from typing import Dict, List, Optional, Tuple

logger = logging.getLogger("NetSentinel.PortScanner")

# Well-known ports to probe — ordered by security relevance
PROBE_PORTS: List[Tuple[int, str]] = [
    (22,   "SSH"),
    (23,   "Telnet"),
    (80,   "HTTP"),
    (443,  "HTTPS"),
    (445,  "SMB"),
    (3389, "RDP"),
    (8080, "HTTP-ALT"),
    (8443, "HTTPS-ALT"),
    (21,   "FTP"),
    (25,   "SMTP"),
    (110,  "POP3"),
    (143,  "IMAP"),
    (5900, "VNC"),
    (1883, "MQTT"),
    (9100, "RAW-PRINT"),
]

# Ports that are always security-notable when open on non-servers
SECURITY_NOTABLE_PORTS = {23, 445, 3389, 5900, 1883, 21}

CONNECT_TIMEOUT = 0.8   # seconds per port
BANNER_TIMEOUT  = 1.0   # seconds to read banner after connect
MAX_BANNER_BYTES = 256


async def _probe_single_port(
    ip: str,
    port: int,
    service_name: str
) -> Optional[Tuple[int, str, Optional[str]]]:
    """
    Attempts a TCP connect to (ip, port).
    Returns (port, service_name, banner_or_None) on success, None if closed/filtered.
    """
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port),
            timeout=CONNECT_TIMEOUT
        )
        banner: Optional[str] = None
        try:
            # Attempt to read a service banner
            raw = await asyncio.wait_for(reader.read(MAX_BANNER_BYTES), timeout=BANNER_TIMEOUT)
            if raw:
                banner = raw.decode("utf-8", errors="replace").strip()
        except Exception:
            pass
        writer.close()
        try:
            await asyncio.wait_for(writer.wait_closed(), timeout=0.3)
        except Exception:
            pass
        logger.debug("Port OPEN: %s:%d (%s) banner=%r", ip, port, service_name, banner)
        return (port, service_name, banner)
    except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
        return None


async def scan_host_ports(
    ip: str,
    ports: Optional[List[Tuple[int, str]]] = None,
    max_concurrent: int = 6
) -> Dict[int, Dict]:
    """
    Scans a single host for open TCP ports with a concurrency limiter.

    Returns a dict keyed by port number:
    {
        22: {"service": "SSH", "banner": "SSH-2.0-OpenSSH_8.9p1...", "is_notable": False},
        445: {"service": "SMB", "banner": None, "is_notable": True},
    }
    """
    probes = ports or PROBE_PORTS
    semaphore = asyncio.Semaphore(max_concurrent)
    open_ports: Dict[int, Dict] = {}

    async def bounded_probe(port: int, svc: str):
        async with semaphore:
            return await _probe_single_port(ip, port, svc)

    tasks = [bounded_probe(port, svc) for port, svc in probes]
    results = await asyncio.gather(*tasks, return_exceptions=True)

    for res in results:
        if isinstance(res, tuple):
            port, service_name, banner = res
            open_ports[port] = {
                "service": service_name,
                "banner": banner,
                "is_notable": port in SECURITY_NOTABLE_PORTS
            }

    logger.info("Port scan complete for %s — %d open ports found", ip, len(open_ports))
    return open_ports


def extract_banners(open_ports: Dict[int, Dict]) -> Dict[int, str]:
    """Extracts a flat {port: banner_str} dict for the fingerprinter."""
    return {
        port: info["banner"]
        for port, info in open_ports.items()
        if info.get("banner")
    }
