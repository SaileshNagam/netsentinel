"""
NetSentinel Lightweight Reachability Inspector & Subnet ARP Warmer
Performs non-intrusive TCP connect probes to test device responsiveness and
passively warms the OS kernel ARP cache across the detected local subnet.
Requires NO raw sockets and NO elevated root privileges.
"""
import asyncio
import socket
import logging
import ipaddress
from typing import List, Dict, Any, Optional

logger = logging.getLogger("NetSentinel.Reachability")

# Quick ports commonly open or responsive to TCP RST on LAN endpoints
PROBE_PORTS = [80, 443, 22, 53, 445, 8080]

async def check_host_reachability(ip: str, timeout: float = 0.4) -> bool:
    """
    Tests if a host is reachable using non-intrusive TCP handshake attempts.
    Returns True if connection succeeds OR is actively refused (RST received means host is up!).
    """
    for port in (80, 443, 22, 53):
        try:
            _, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, port),
                timeout=timeout
            )
            writer.close()
            try:
                await asyncio.wait_for(writer.wait_closed(), timeout=0.2)
            except Exception:
                pass
            return True
        except ConnectionRefusedError:
            # Active RST packet received -> host is definitely UP!
            return True
        except (asyncio.TimeoutError, OSError):
            continue
    return False

async def warm_subnet_arp_cache(cidr: str, max_concurrent: int = 50) -> int:
    """
    Concurrently sends non-blocking TCP connect attempts to common ports across the CIDR.
    Even if the TCP connection times out, the operating system's network stack MUST send an
    ARP request to resolve the IP's MAC address, thereby refreshing the OS kernel ARP cache!
    
    This ensures `arp -an` contains active Wi-Fi endpoints without requiring root/raw packets.
    """
    try:
        network = ipaddress.ip_network(cidr, strict=False)
    except ValueError:
        return 0

    # Limit to /24 or smaller to prevent excessive traffic
    hosts = list(network.hosts())
    if len(hosts) > 256:
        hosts = hosts[:256]

    sem = asyncio.Semaphore(max_concurrent)

    async def probe_ip(ip_str: str):
        async with sem:
            # Try port 80 with ultra-short 120ms timeout just to trigger OS ARP request
            try:
                _, writer = await asyncio.wait_for(
                    asyncio.open_connection(ip_str, 80),
                    timeout=0.12
                )
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass

    tasks = [probe_ip(str(h)) for h in hosts]
    await asyncio.gather(*tasks, return_exceptions=True)
    logger.debug("Subnet ARP warming complete for %d hosts in %s", len(hosts), cidr)
    return len(hosts)
