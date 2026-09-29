"""
NetSentinel Local Route & Interface Inspector
Automatically detects the active network interface, calculates the local IPv4 CIDR,
subnet mask, default gateway, and network address.
Strictly filters out virtual, loopback, Docker, and tunnel interfaces unless they carry the default route.
"""
import subprocess
import re
import socket
import ipaddress
import psutil
from typing import Dict, Any, Optional, List
from app.core.database import settings

# Common virtual/tunnel interface prefixes to ignore unless default route
IGNORED_IFACE_PREFIXES = (
    "lo", "docker", "veth", "br-", "vmnet", "vboxnet", 
    "utun", "tun", "tap", "gif", "stf", "p2p", "awdl", "llw"
)

def get_default_gateway() -> Optional[Dict[str, str]]:
    """
    Extracts the default gateway IP and interface from system routing table.
    Supports macOS (netstat -rn), Linux (ip route / /proc/net/route), and Windows (route print).
    """
    # 1. macOS / BSD netstat -rn
    try:
        output = subprocess.check_output(
            ["/usr/sbin/netstat", "-rn"],
            stderr=subprocess.DEVNULL,
            timeout=2
        ).decode()
        for line in output.splitlines():
            parts = line.split()
            if len(parts) >= 4 and parts[0] == "default":
                gw_ip = parts[1]
                # Validate IPv4 format
                if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", gw_ip):
                    iface = parts[3] if len(parts) > 3 else "en0"
                    # Strip scope if present (e.g. en0%...)
                    iface = iface.split("%")[0]
                    return {"gateway_ip": gw_ip, "interface": iface}
    except Exception:
        pass

    # 2. Linux ip route
    try:
        output = subprocess.check_output(
            ["ip", "route", "show", "default"],
            stderr=subprocess.DEVNULL,
            timeout=2
        ).decode()
        # default via 192.168.1.1 dev eth0
        parts = output.split()
        if len(parts) >= 5 and parts[0] == "default" and parts[1] == "via":
            gw_ip = parts[2]
            iface = parts[4]
            return {"gateway_ip": gw_ip, "interface": iface}
    except Exception:
        pass

    # 3. Fallback: query default interface via socket routing trick (doesn't send packet)
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 53))
        local_ip = s.getsockname()[0]
        s.close()
        # Find which interface owns this local IP
        for iface_name, addrs in psutil.net_if_addrs().items():
            for a in addrs:
                if a.family == socket.AF_INET and a.address == local_ip:
                    # Guess gateway as .1 on that subnet
                    ip_parts = local_ip.split(".")
                    gw_guess = f"{ip_parts[0]}.{ip_parts[1]}.{ip_parts[2]}.1"
                    return {"gateway_ip": gw_guess, "interface": iface_name}
    except Exception:
        pass

    return {"gateway_ip": "192.168.1.1", "interface": "en0"}

def get_active_network_info() -> Dict[str, Any]:
    """
    Determines the active primary network interface and its network configuration.
    Returns:
    {
        "interface": "en0",
        "ip_address": "192.168.1.240",
        "netmask": "255.255.255.0",
        "cidr": "192.168.1.0/24",
        "network_address": "192.168.1.0",
        "broadcast_address": "192.168.1.255",
        "gateway_ip": "192.168.1.1",
        "mac_address": "...",
        "is_rfc1918": True
    }
    """
    gw_info = get_default_gateway() or {"gateway_ip": "192.168.1.1", "interface": "en0"}
    target_iface = gw_info["interface"]
    gateway_ip = gw_info["gateway_ip"]

    addrs = psutil.net_if_addrs()
    stats = psutil.net_if_stats()

    selected_info = None

    # First attempt: lookup interface associated with default gateway
    if target_iface in addrs:
        selected_info = _extract_iface_ipv4(target_iface, addrs[target_iface], gateway_ip)

    # If not found, look for any active non-virtual interface with an RFC 1918 IP
    if not selected_info:
        for iface_name, addr_list in addrs.items():
            if any(iface_name.lower().startswith(prefix) for prefix in IGNORED_IFACE_PREFIXES):
                continue
            stat = stats.get(iface_name)
            if stat and not stat.isup:
                continue
            candidate = _extract_iface_ipv4(iface_name, addr_list, gateway_ip)
            if candidate and candidate["is_rfc1918"]:
                selected_info = candidate
                break

    # Final fallback if completely disconnected
    if not selected_info:
        return {
            "interface": target_iface,
            "ip_address": "127.0.0.1",
            "netmask": "255.0.0.0",
            "cidr": "127.0.0.0/8",
            "network_address": "127.0.0.0",
            "broadcast_address": "127.255.255.255",
            "gateway_ip": gateway_ip,
            "mac_address": None,
            "is_rfc1918": False
        }

    return selected_info

def _extract_iface_ipv4(iface_name: str, addr_list: list, gateway_ip: str) -> Optional[Dict[str, Any]]:
    ipv4_addr = None
    netmask = None
    broadcast = None
    mac_addr = None

    for a in addr_list:
        if a.family == socket.AF_INET:
            ipv4_addr = a.address
            netmask = a.netmask or "255.255.255.0"
            broadcast = a.broadcast
        elif getattr(socket, "AF_LINK", None) and a.family == socket.AF_LINK:
            mac_addr = a.address

    if not ipv4_addr or ipv4_addr.startswith("127."):
        return None

    try:
        if_net = ipaddress.IPv4Network(f"{ipv4_addr}/{netmask}", strict=False)
        cidr_str = str(if_net)
        net_addr = str(if_net.network_address)
        bcast_addr = broadcast or str(if_net.broadcast_address)
        is_priv = if_net.is_private
    except Exception:
        # Fallback to standard /24
        octets = ipv4_addr.split(".")
        cidr_str = f"{octets[0]}.{octets[1]}.{octets[2]}.0/24"
        net_addr = f"{octets[0]}.{octets[1]}.{octets[2]}.0"
        bcast_addr = f"{octets[0]}.{octets[1]}.{octets[2]}.255"
        is_priv = settings.is_ip_authorized(ipv4_addr)

    return {
        "interface": iface_name,
        "ip_address": ipv4_addr,
        "netmask": netmask,
        "subnet_mask": netmask,
        "cidr": cidr_str,
        "network_address": net_addr,
        "broadcast_address": bcast_addr,
        "gateway_ip": gateway_ip,
        "mac_address": mac_addr,
        "is_rfc1918": is_priv
    }

def get_local_interfaces() -> List[Dict[str, Any]]:
    """
    Enumerates all active local network interfaces, addresses, and authorized subnet CIDRs.
    """
    interfaces = []
    addrs = psutil.net_if_addrs()
    stats = psutil.net_if_stats()

    for iface_name, addr_list in addrs.items():
        stat = stats.get(iface_name)
        is_up = stat.isup if stat else True
        if iface_name.startswith("lo") or not is_up:
            continue

        ipv4_info = None
        ipv6_info = []
        mac_addr = None

        for a in addr_list:
            if a.family == socket.AF_INET:
                if settings.is_ip_authorized(a.address):
                    ipv4_info = {
                        "ip": a.address,
                        "netmask": a.netmask or "255.255.255.0",
                        "broadcast": a.broadcast
                    }
            elif a.family == socket.AF_INET6:
                if not a.address.startswith("fe80::1%lo0") and not a.address.startswith("::1"):
                    ipv6_info.append(a.address.split("%")[0])
            elif getattr(socket, "AF_LINK", None) and a.family == socket.AF_LINK:
                mac_addr = a.address

        if ipv4_info:
            # Calculate CIDR
            try:
                network = ipaddress.IPv4Network(f"{ipv4_info['ip']}/{ipv4_info['netmask']}", strict=False)
                cidr = str(network)
            except Exception:
                cidr = f"{ipv4_info['ip']}/24"

            interfaces.append({
                "interface": iface_name,
                "ip": ipv4_info["ip"],
                "netmask": ipv4_info["netmask"],
                "cidr": cidr,
                "broadcast": ipv4_info["broadcast"],
                "mac": mac_addr,
                "ipv6": ipv6_info[:3],
                "is_up": is_up
            })

    return interfaces
