"""
NetSentinel Safe Hostname Resolver
Attempts safe, multi-vector hostname identification without hallucination.
Never fabricates names. If no definitive signal is found, returns 'Unknown'.
"""
import socket
import logging
from typing import Optional

logger = logging.getLogger("NetSentinel.HostnameResolver")

def resolve_hostname(ip: str) -> str:
    """
    Attempts to identify the endpoint's real hostname via:
    1. Safe Reverse DNS lookup (socket.gethostbyaddr with short timeout)
    2. Local mDNS name query (if .local resolution is enabled in resolver)

    Returns:
        Actual resolved hostname string, or "Unknown" if not found.
    """
    if not ip or ip in ("127.0.0.1", "0.0.0.0"):
        return "Unknown"

    old_timeout = socket.getdefaulttimeout()
    try:
        # Strict timeout to avoid blocking discovery loop
        socket.setdefaulttimeout(0.35)
        name, aliases, _ = socket.gethostbyaddr(ip)
        
        # Check if reverse DNS returned a valid non-IP string
        if name and name != ip and not name.startswith("ip-") and not name.replace(".", "").isdigit():
            # If name ends with dot, strip it
            name = name.rstrip(".")
            return name
        
        # Check aliases
        for alias in aliases:
            if alias and alias != ip:
                return alias.rstrip(".")
    except (socket.herror, socket.gaierror, socket.timeout, OSError):
        pass
    finally:
        socket.setdefaulttimeout(old_timeout)

    return "Unknown"
