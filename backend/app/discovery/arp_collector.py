"""
NetSentinel Kernel Neighbor / ARP Cache Collector
Parses OS ARP tables safely across macOS, Linux, and Windows using safe subprocess execution.
Filters broadcast, multicast, incomplete, and non-RFC1918 entries.
"""
import subprocess
import re
import os
import sys
from typing import List, Dict, Any
from app.core.database import settings
from app.core.oui_database import normalize_mac

def parse_macos_arp(output: str) -> List[Dict[str, Any]]:
    """
    Parses BSD/macOS `arp -an` output:
    ? (192.168.1.1) at 20:c:86:20:9b:da on en0 ifscope [ethernet]
    """
    devices = []
    pattern = re.compile(r"\?\s+\(([0-9\.]+)\)\s+at\s+([0-9a-fA-F\:]+)\s+on\s+([a-zA-Z0-9]+)")
    
    for line in output.splitlines():
        line = line.strip()
        if "incomplete" in line:
            continue
        match = pattern.search(line)
        if match:
            ip, raw_mac, iface = match.groups()
            if ip.endswith(".255") or ip.startswith("224.") or raw_mac.lower() in ("ff:ff:ff:ff:ff:ff", "(incomplete)"):
                continue
            if not settings.is_ip_authorized(ip):
                continue

            normalized_mac = normalize_mac(raw_mac)
            if normalized_mac:
                devices.append({
                    "ip": ip,
                    "mac": normalized_mac,
                    "interface": iface,
                    "discovery_method": "KERNEL_ARP_CACHE"
                })
    return devices

def parse_linux_ip_neigh(output: str) -> List[Dict[str, Any]]:
    """
    Parses Linux `ip neigh` output:
    192.168.1.1 dev eth0 lladdr 20:0c:86:20:9b:da REACHABLE
    """
    devices = []
    for line in output.splitlines():
        parts = line.strip().split()
        if len(parts) >= 4 and "lladdr" in parts:
            ip = parts[0]
            try:
                lladdr_idx = parts.index("lladdr")
                raw_mac = parts[lladdr_idx + 1]
                iface = parts[parts.index("dev") + 1] if "dev" in parts else "eth0"
                if "FAILED" in parts or "INCOMPLETE" in parts or raw_mac.lower() in ("00:00:00:00:00:00", "ff:ff:ff:ff:ff:ff"):
                    continue
                if not settings.is_ip_authorized(ip):
                    continue
                normalized_mac = normalize_mac(raw_mac)
                if normalized_mac:
                    devices.append({
                        "ip": ip,
                        "mac": normalized_mac,
                        "interface": iface,
                        "discovery_method": "KERNEL_ARP_CACHE"
                    })
            except Exception:
                continue
    return devices

def parse_linux_arp() -> List[Dict[str, Any]]:
    """
    Parses Linux `/proc/net/arp`.
    """
    devices = []
    if not os.path.exists("/proc/net/arp"):
        return devices
    try:
        with open("/proc/net/arp", "r") as f:
            lines = f.readlines()[1:]
        for line in lines:
            parts = line.split()
            if len(parts) >= 6:
                ip, hw_type, flags, raw_mac, mask, iface = parts[:6]
                if flags == "0x0" or raw_mac in ("00:00:00:00:00:00", "ff:ff:ff:ff:ff:ff"):
                    continue
                if not settings.is_ip_authorized(ip):
                    continue
                normalized_mac = normalize_mac(raw_mac)
                if normalized_mac:
                    devices.append({
                        "ip": ip,
                        "mac": normalized_mac,
                        "interface": iface,
                        "discovery_method": "KERNEL_ARP_CACHE"
                    })
    except Exception:
        pass
    return devices

def parse_windows_arp(output: str) -> List[Dict[str, Any]]:
    """
    Parses Windows `arp -a` output:
    192.168.1.1          20-0c-86-20-9b-da     dynamic
    """
    devices = []
    pattern = re.compile(r"([0-9\.]+)\s+([0-9a-fA-F\-]{17})\s+(\w+)")
    for line in output.splitlines():
        match = pattern.search(line.strip())
        if match:
            ip, raw_mac, entry_type = match.groups()
            if entry_type.lower() == "invalid" or ip.endswith(".255") or ip.startswith("224."):
                continue
            if not settings.is_ip_authorized(ip):
                continue
            normalized_mac = normalize_mac(raw_mac)
            if normalized_mac and normalized_mac != "ff:ff:ff:ff:ff:ff":
                devices.append({
                    "ip": ip,
                    "mac": normalized_mac,
                    "interface": "Windows-LAN",
                    "discovery_method": "KERNEL_ARP_CACHE"
                })
    return devices

def collect_arp_devices() -> List[Dict[str, Any]]:
    """
    Queries operating system kernel neighbor/ARP tables safely.
    """
    # 1. macOS / BSD arp -an
    try:
        output = subprocess.check_output(
            ["/usr/sbin/arp", "-an"],
            stderr=subprocess.DEVNULL,
            timeout=2
        ).decode()
        macos_devs = parse_macos_arp(output)
        if macos_devs:
            return macos_devs
    except Exception:
        pass

    # 2. Linux ip neigh
    try:
        output = subprocess.check_output(
            ["ip", "neigh"],
            stderr=subprocess.DEVNULL,
            timeout=2
        ).decode()
        linux_neigh = parse_linux_ip_neigh(output)
        if linux_neigh:
            return linux_neigh
    except Exception:
        pass

    # 3. Linux /proc/net/arp
    linux_devs = parse_linux_arp()
    if linux_devs:
        return linux_devs

    # 4. Windows arp -a
    try:
        output = subprocess.check_output(
            ["arp", "-a"],
            stderr=subprocess.DEVNULL,
            timeout=2
        ).decode()
        return parse_windows_arp(output)
    except Exception:
        pass

    return []
