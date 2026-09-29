"""
NetSentinel IEEE OUI Vendor Database & MAC Randomization Analyzer
"""
import re
from typing import Tuple, Optional

# Embedded IEEE OUI prefix database for common vendors
OUI_MAP = {
    # Apple
    "00:03:93": "Apple, Inc.",
    "00:05:02": "Apple, Inc.",
    "00:0a:27": "Apple, Inc.",
    "00:0a:95": "Apple, Inc.",
    "00:0d:93": "Apple, Inc.",
    "00:10:fa": "Apple, Inc.",
    "00:11:24": "Apple, Inc.",
    "00:14:51": "Apple, Inc.",
    "00:16:cb": "Apple, Inc.",
    "00:17:f2": "Apple, Inc.",
    "00:19:e3": "Apple, Inc.",
    "00:1b:63": "Apple, Inc.",
    "00:1c:b3": "Apple, Inc.",
    "00:1d:4f": "Apple, Inc.",
    "00:1e:52": "Apple, Inc.",
    "00:1e:c2": "Apple, Inc.",
    "00:1f:5b": "Apple, Inc.",
    "00:1f:f3": "Apple, Inc.",
    "00:21:e9": "Apple, Inc.",
    "00:22:41": "Apple, Inc.",
    "00:23:12": "Apple, Inc.",
    "00:23:32": "Apple, Inc.",
    "00:23:6c": "Apple, Inc.",
    "00:23:df": "Apple, Inc.",
    "00:24:36": "Apple, Inc.",
    "00:25:00": "Apple, Inc.",
    "00:25:4b": "Apple, Inc.",
    "00:25:bc": "Apple, Inc.",
    "00:26:08": "Apple, Inc.",
    "00:26:4a": "Apple, Inc.",
    "00:26:b0": "Apple, Inc.",
    "00:26:bb": "Apple, Inc.",
    "f0:18:98": "Apple, Inc.",
    "a4:83:e7": "Apple, Inc.",
    "3c:22:fb": "Apple, Inc.",
    "ac:bc:32": "Apple, Inc.",
    "8c:85:90": "Apple, Inc.",
    "78:7b:8a": "Apple, Inc.",
    "14:7d:da": "Apple, Inc.",
    "a8:3b:76": "Apple, Inc.",
    "60:f4:45": "Apple, Inc.",
    "f0:d1:a9": "Apple, Inc.",
    "f4:5c:89": "Apple, Inc.",
    
    # Samsung Electronics
    "cc:47:40": "Samsung Electronics",
    "00:00:f0": "Samsung Electronics",
    "00:07:ab": "Samsung Electronics",
    "00:12:47": "Samsung Electronics",
    "00:15:b9": "Samsung Electronics",
    "00:16:6b": "Samsung Electronics",
    "00:16:6c": "Samsung Electronics",
    "00:17:c9": "Samsung Electronics",
    "00:17:d5": "Samsung Electronics",
    "00:18:af": "Samsung Electronics",
    "00:1a:8a": "Samsung Electronics",
    "00:1d:25": "Samsung Electronics",
    "00:21:19": "Samsung Electronics",
    "00:21:4c": "Samsung Electronics",
    "00:21:d1": "Samsung Electronics",
    "00:21:d2": "Samsung Electronics",
    "00:23:39": "Samsung Electronics",
    "00:23:99": "Samsung Electronics",
    "00:23:c3": "Samsung Electronics",
    "00:24:54": "Samsung Electronics",
    "00:24:91": "Samsung Electronics",
    "00:26:37": "Samsung Electronics",
    "00:26:5d": "Samsung Electronics",
    "5c:49:7d": "Samsung Electronics",
    "e4:7c:f9": "Samsung Electronics",
    
    # Google & Nest
    "00:1a:11": "Google, Inc.",
    "3c:5a:b4": "Google, Inc.",
    "54:60:09": "Google, Inc.",
    "64:16:66": "Google, Inc.",
    "94:eb:cd": "Google, Inc.",
    "a4:77:33": "Google, Inc.",
    "d8:6c:63": "Google, Inc.",
    "f8:8f:ca": "Google, Inc.",
    "18:b4:30": "Nest Labs",
    "64:16:6d": "Nest Labs",
    
    # Raspberry Pi Foundation
    "b8:27:eb": "Raspberry Pi Foundation",
    "dc:a6:32": "Raspberry Pi Trading Ltd",
    "e4:5f:01": "Raspberry Pi Trading Ltd",
    "28:cd:c1": "Raspberry Pi Trading Ltd",
    
    # Espressif (ESP8266 / ESP32 IoT)
    "18:fe:34": "Espressif Systems",
    "24:0a:c4": "Espressif Systems",
    "24:6f:28": "Espressif Systems",
    "30:ae:a4": "Espressif Systems",
    "a4:cf:12": "Espressif Systems",
    "d8:bf:c0": "Espressif Systems",
    "ec:fa:bc": "Espressif Systems",
    
    # Intel
    "00:02:b3": "Intel Corporate",
    "00:03:47": "Intel Corporate",
    "00:04:23": "Intel Corporate",
    "00:0e:0c": "Intel Corporate",
    "00:13:02": "Intel Corporate",
    "00:13:e8": "Intel Corporate",
    "00:15:00": "Intel Corporate",
    "00:16:6f": "Intel Corporate",
    "00:16:76": "Intel Corporate",
    "00:16:ea": "Intel Corporate",
    "00:16:eb": "Intel Corporate",
    "00:18:de": "Intel Corporate",
    "00:19:d1": "Intel Corporate",
    "00:1b:21": "Intel Corporate",
    "00:1b:77": "Intel Corporate",
    "00:1c:c0": "Intel Corporate",
    "00:1d:e0": "Intel Corporate",
    "00:1e:64": "Intel Corporate",
    "00:1e:65": "Intel Corporate",
    "00:1e:67": "Intel Corporate",
    "00:1f:3b": "Intel Corporate",
    "00:1f:3c": "Intel Corporate",
    "00:21:5c": "Intel Corporate",
    "00:21:6a": "Intel Corporate",
    "00:21:6b": "Intel Corporate",
    "00:22:fa": "Intel Corporate",
    "00:22:fb": "Intel Corporate",
    "00:23:14": "Intel Corporate",
    "00:23:15": "Intel Corporate",
    "00:24:d6": "Intel Corporate",
    "00:24:d7": "Intel Corporate",
    "00:26:c6": "Intel Corporate",
    "00:26:c7": "Intel Corporate",
    
    # Cisco & Linksys
    "00:00:0c": "Cisco Systems",
    "00:01:42": "Cisco Systems",
    "00:01:43": "Cisco Systems",
    "00:01:63": "Cisco Systems",
    "00:01:64": "Cisco Systems",
    "00:01:96": "Cisco Systems",
    "00:01:97": "Cisco Systems",
    "00:01:c7": "Cisco Systems",
    "00:01:c9": "Cisco Systems",
    "00:02:16": "Cisco Systems",
    "00:02:17": "Cisco Systems",
    "00:02:4a": "Cisco Systems",
    "00:02:4b": "Cisco Systems",
    "00:02:7d": "Cisco Systems",
    "00:02:7e": "Cisco Systems",
    "00:02:b9": "Cisco Systems",
    "00:02:ba": "Cisco Systems",
    "00:02:fc": "Cisco Systems",
    "00:02:fd": "Cisco Systems",
    "00:03:6b": "Cisco Systems",
    "00:03:6c": "Cisco Systems",
    "00:04:27": "Cisco Systems",
    "00:04:28": "Cisco Systems",
    "00:04:4d": "Cisco Systems",
    "00:04:4e": "Cisco Systems",
    "00:04:9a": "Cisco Systems",
    "00:04:9b": "Cisco Systems",
    "00:04:c0": "Cisco Systems",
    "00:04:c1": "Cisco Systems",
    "00:04:dd": "Cisco Systems",
    "00:04:de": "Cisco Systems",
    "00:05:31": "Cisco Systems",
    "00:05:32": "Cisco Systems",
    "00:05:5e": "Cisco Systems",
    "00:05:5f": "Cisco Systems",
    "00:05:73": "Cisco Systems",
    "00:05:74": "Cisco Systems",
    "00:05:9a": "Cisco Systems",
    "00:05:9b": "Cisco Systems",
    "00:05:dc": "Cisco Systems",
    "00:05:dd": "Cisco Systems",
    
    # TP-Link
    "20:0c:86": "TP-Link Technologies",
    "00:0a:eb": "TP-Link Technologies",
    "00:14:78": "TP-Link Technologies",
    "00:19:e0": "TP-Link Technologies",
    "00:21:27": "TP-Link Technologies",
    "00:23:cd": "TP-Link Technologies",
    "00:25:86": "TP-Link Technologies",
    "14:cf:92": "TP-Link Technologies",
    "50:c7:bf": "TP-Link Technologies",
    "ec:08:6b": "TP-Link Technologies",
    
    # Xiaomi Communications
    "90:cd:e8": "Xiaomi Communications",
    "00:92:35": "Chicony Electronics",
    "48:f1:7f": "Motorola Mobility (Lenovo)",
    
    # Ubiquiti Networks
    "00:15:6d": "Ubiquiti Networks",
    "00:27:22": "Ubiquiti Networks",
    "24:a4:3c": "Ubiquiti Networks",
    "68:d7:9a": "Ubiquiti Networks",
    "78:8a:20": "Ubiquiti Networks",
    "b4:fb:e4": "Ubiquiti Networks",
    "e0:63:da": "Ubiquiti Networks",
    "fc:ec:da": "Ubiquiti Networks",
    
    # Synology
    "00:11:32": "Synology Incorporated",
    
    # Amazon Technologies
    "00:fc:8b": "Amazon Technologies",
    "38:f7:3d": "Amazon Technologies",
    "40:b4:cd": "Amazon Technologies",
    "44:65:0d": "Amazon Technologies",
    "50:dc:e7": "Amazon Technologies",
    "68:37:e9": "Amazon Technologies",
    "68:54:fd": "Amazon Technologies",
    "74:c2:46": "Amazon Technologies",
    "fc:65:de": "Amazon Technologies",
    
    # Microsoft
    "00:03:ff": "Microsoft Corporation",
    "00:0d:3a": "Microsoft Corporation",
    "00:12:5a": "Microsoft Corporation",
    "00:15:5d": "Microsoft Corporation",
    "00:17:fa": "Microsoft Corporation",
    "00:1d:d8": "Microsoft Corporation",
    "28:18:78": "Microsoft Corporation",
    "dc:98:40": "Microsoft Corporation",
    
    # Sony
    "00:01:4a": "Sony Corporation",
    "00:04:1f": "Sony Corporation",
    "00:0a:d9": "Sony Corporation",
    "00:0e:07": "Sony Corporation",
    "00:13:15": "Sony Corporation",
    "00:15:c1": "Sony Corporation",
    "00:19:c5": "Sony Corporation",
    "00:1d:0d": "Sony Corporation",
    "00:1f:a7": "Sony Corporation",
    "00:24:8d": "Sony Corporation",
    "70:9e:29": "Sony Interactive Entertainment",
    
    # Dell
    "00:06:5b": "Dell Inc.",
    "00:08:74": "Dell Inc.",
    "00:0b:db": "Dell Inc.",
    "00:0d:56": "Dell Inc.",
    "00:0f:1f": "Dell Inc.",
    "00:11:43": "Dell Inc.",
    "00:12:3f": "Dell Inc.",
    "00:13:72": "Dell Inc.",
    "00:14:22": "Dell Inc.",
    "00:15:c5": "Dell Inc.",
    "00:16:f0": "Dell Inc.",
    "00:18:8b": "Dell Inc.",
    "00:19:b9": "Dell Inc.",
    "00:1a:a0": "Dell Inc.",
    "00:1c:23": "Dell Inc.",
    "00:1d:09": "Dell Inc.",
    "00:1e:4f": "Dell Inc.",
    "00:1e:c9": "Dell Inc.",
    "00:21:70": "Dell Inc.",
    "00:21:9b": "Dell Inc.",
    "00:22:19": "Dell Inc.",
    "00:23:ae": "Dell Inc.",
    "00:24:e8": "Dell Inc.",
    "00:25:64": "Dell Inc.",
    "00:26:b9": "Dell Inc.",
}

def normalize_mac(mac: Optional[str]) -> Optional[str]:
    """
    Standardizes a MAC address string into lowercase colon-separated format (aa:bb:cc:dd:ee:ff).
    Robustly pads single-digit octets from BSD/macOS arp output (e.g. 20:c:86 -> 20:0c:86).
    Returns None if invalid.
    """
    if not mac:
        return None
    mac_str = mac.strip().lower()
    if ":" in mac_str or "-" in mac_str:
        delim = ":" if ":" in mac_str else "-"
        parts = mac_str.split(delim)
        if len(parts) == 6:
            try:
                padded = [f"{int(p, 16):02x}" for p in parts]
                return ":".join(padded)
            except ValueError:
                return None
    cleaned = re.sub(r"[^0-9a-fA-F]", "", mac_str)
    if len(cleaned) != 12:
        return None
    return ":".join(cleaned[i:i+2] for i in range(0, 12, 2))

def is_locally_administered(mac: str) -> bool:
    """
    Evaluates the IEEE 802 Locally Administered Address (LAA) bit.
    Bit 1 of Byte 0 indicates whether the MAC was assigned by IEEE (0) 
    or dynamically generated / randomized (1).
    """
    normalized = normalize_mac(mac)
    if not normalized:
        return False
    try:
        first_byte = int(normalized.split(":")[0], 16)
        # Check bit 1 (0x02)
        return bool(first_byte & 0x02)
    except ValueError:
        return False

def is_multicast_mac(mac: str) -> bool:
    """
    Checks if the Individual/Group bit is set (multicast/broadcast).
    """
    normalized = normalize_mac(mac)
    if not normalized:
        return False
    try:
        first_byte = int(normalized.split(":")[0], 16)
        return bool(first_byte & 0x01)
    except ValueError:
        return False

def resolve_mac_vendor(mac: Optional[str]) -> Tuple[str, bool, str]:
    """
    Resolves MAC vendor and randomization status.
    Returns: (vendor_name, is_randomized, confidence)
    """
    normalized = normalize_mac(mac)
    if not normalized:
        return "Unknown / Unresolved", False, "UNKNOWN"
    
    # Check for MAC randomization first
    is_random = is_locally_administered(normalized)
    if is_random:
        return "Randomized / Private MAC (LAA)", True, "CONFIRMED"
    
    # Look up OUI prefix (first 3 octets)
    prefix = ":".join(normalized.split(":")[:3])
    if prefix in OUI_MAP:
        return OUI_MAP[prefix], False, "CONFIRMED"
    
    return "Unregistered OUI Vendor", False, "LOW"
