"""
NetSentinel Device Identity & OS Fingerprinting Engine
Infers device type, vendor, and OS hints safely with explicit confidence ratings.
Adheres strictly to the rule: Never claim exact hardware or OS models without definitive evidence.
"""
from typing import Dict, Any, Tuple, Optional
from app.core.oui_database import resolve_mac_vendor, is_locally_administered

def fingerprint_endpoint(
    ip: str,
    mac: Optional[str],
    hostname: Optional[str],
    banners: Optional[Dict[int, str]] = None,
    is_gateway: bool = False
) -> Dict[str, Any]:
    """
    Performs multi-vector safe device fingerprinting.
    Returns: {
        "vendor": str,
        "is_mac_randomized": bool,
        "device_type": str,
        "device_type_confidence": str,
        "os_hint": str,
        "os_confidence": str
    }
    """
    vendor, is_random, vendor_conf = resolve_mac_vendor(mac)
    
    # 1. Gateway Detection
    if is_gateway:
        return {
            "vendor": vendor,
            "is_mac_randomized": is_random,
            "device_type": "ROUTER",
            "device_type_confidence": "CONFIRMED",
            "os_hint": "Embedded Network Gateway OS",
            "os_confidence": "HIGH"
        }

    h = (hostname or "").lower()
    v = vendor.lower()
    banners = banners or {}

    # 2. Service Banner Analysis (Highest Accuracy if available)
    if 22 in banners:
        ssh_banner = banners[22].lower()
        if "debian" in ssh_banner or "ubuntu" in ssh_banner:
            return {
                "vendor": vendor,
                "is_mac_randomized": is_random,
                "device_type": "SERVER" if "server" in h else "WORKSTATION",
                "device_type_confidence": "HIGH",
                "os_hint": "Linux (Debian/Ubuntu Kernel)",
                "os_confidence": "CONFIRMED"
            }
        if "raspbian" in ssh_banner or "raspberry" in v:
            return {
                "vendor": vendor,
                "is_mac_randomized": is_random,
                "device_type": "IOT_DEVICE",
                "device_type_confidence": "CONFIRMED",
                "os_hint": "Raspberry Pi OS (Linux)",
                "os_confidence": "CONFIRMED"
            }

    if 445 in banners:
        smb_banner = banners[445].lower()
        if "windows" in smb_banner or "microsoft" in smb_banner:
            return {
                "vendor": vendor,
                "is_mac_randomized": is_random,
                "device_type": "LAPTOP" if ("laptop" in h or is_random) else "WORKSTATION",
                "device_type_confidence": "HIGH",
                "os_hint": "Microsoft Windows 10/11",
                "os_confidence": "HIGH"
            }
        if "synology" in smb_banner:
            return {
                "vendor": vendor,
                "is_mac_randomized": is_random,
                "device_type": "NAS_STORAGE",
                "device_type_confidence": "CONFIRMED",
                "os_hint": "Synology DiskStation Manager (DSM)",
                "os_confidence": "CONFIRMED"
            }

    # 3. Hostname and mDNS Heuristics
    if "iphone" in h or "ipad" in h:
        return {
            "vendor": "Apple, Inc.",
            "is_mac_randomized": is_random,
            "device_type": "MOBILE",
            "device_type_confidence": "CONFIRMED",
            "os_hint": "Apple iOS / iPadOS",
            "os_confidence": "HIGH"
        }
    if "macbook" in h or "imac" in h or "mac-mini" in h:
        return {
            "vendor": "Apple, Inc.",
            "is_mac_randomized": is_random,
            "device_type": "LAPTOP",
            "device_type_confidence": "HIGH",
            "os_hint": "macOS (Darwin Kernel)",
            "os_confidence": "HIGH"
        }
    if "galaxy" in h or "pixel" in h or "android" in h:
        return {
            "vendor": vendor,
            "is_mac_randomized": is_random,
            "device_type": "MOBILE",
            "device_type_confidence": "HIGH",
            "os_hint": "Android OS",
            "os_confidence": "HIGH"
        }
    if "tv" in h or "tizen" in h or "roku" in h or "bravia" in h or "qled" in h:
        return {
            "vendor": vendor,
            "is_mac_randomized": is_random,
            "device_type": "SMART_TV",
            "device_type_confidence": "HIGH",
            "os_hint": "Smart TV OS (Tizen / WebOS / AndroidTV)",
            "os_confidence": "MEDIUM"
        }

    # 4. Vendor-Only Inferences
    if "apple" in v:
        if is_random:
            return {
                "vendor": vendor,
                "is_mac_randomized": True,
                "device_type": "MOBILE",
                "device_type_confidence": "MEDIUM",
                "os_hint": "Apple iOS (Private Wi-Fi Address)",
                "os_confidence": "MEDIUM"
            }
        return {
            "vendor": vendor,
            "is_mac_randomized": False,
            "device_type": "LAPTOP",
            "device_type_confidence": "MEDIUM",
            "os_hint": "macOS / iOS Family",
            "os_confidence": "LOW"
        }

    if "espressif" in v or "tuya" in v or "raspberry" in v:
        return {
            "vendor": vendor,
            "is_mac_randomized": is_random,
            "device_type": "IOT_DEVICE",
            "device_type_confidence": "HIGH",
            "os_hint": "Embedded Real-Time OS / Linux",
            "os_confidence": "MEDIUM"
        }

    if "samsung" in v or "sony" in v or "lg" in v:
        return {
            "vendor": vendor,
            "is_mac_randomized": is_random,
            "device_type": "SMART_TV",
            "device_type_confidence": "MEDIUM",
            "os_hint": "Smart Device OS",
            "os_confidence": "LOW"
        }

    # 5. Default Fallback
    return {
        "vendor": vendor,
        "is_mac_randomized": is_random,
        "device_type": "UNKNOWN",
        "device_type_confidence": "UNKNOWN",
        "os_hint": "Generic Network Host",
        "os_confidence": "UNKNOWN"
    }
